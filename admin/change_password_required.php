<?php
/**
 * Forced password-change destination — Layer 2 of the default-password
 * protection (see config/banner_warnings.inc for the redirect logic).
 *
 * Reached only when the operator is connecting from a remote subnet
 * AND still using the factory default basic-auth password. Renders a
 * single-purpose form: change the password, nothing else.
 *
 * The htpasswd / chpasswd update flow is a verbatim mirror of the
 * password-change section in admin/configure.php (~line 440 onward).
 * Keep the two in sync — any future fix to one belongs in the other.
 *
 * On success: redirect to /admin/. The Layer 2 trigger will no longer
 * fire (password is no longer 'raspberry'), so the operator returns
 * to normal dashboard navigation.
 *
 * Direct-URL access by an operator who is NOT using the default
 * password just redirects to /admin/ — the page is only useful when
 * the trigger condition holds.
 */

require_once($_SERVER['DOCUMENT_ROOT'] . '/config/security_headers.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/config/csrf.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/config/banner_warnings.inc');
setSecurityHeaders();

// CSRF: rejects forged POSTs cleanly with 403 before any chpasswd /
// htpasswd side-effect. Bootstraps the session on GET so the token
// cookie ships with the form render.
csrf_verify();

// If the operator's password is NOT the default, they don't need
// this page. Send them to the main admin dashboard.
//
// Done BEFORE any HTML output so the redirect is clean.
if (!_pistar_default_password_in_use()) {
    header('Location: /admin/', true, 302);
    exit;
}

require_once('../config/language.php');
$pistarReleaseConfig = '/etc/pistar-release';
$configPistarRelease = parse_ini_file($pistarReleaseConfig, true);
require_once('../config/version.php');

// Mirror of admin/configure.php password change (~line 440). Keep
// these two paths byte-equivalent so a fix to one always lands in
// the other. proc_open() + stdin pipes — password never on argv,
// never reaches a shell. chpasswd FIRST so PAM rejection blocks
// the htpasswd write and keeps web/shell auth in sync.
//
// Two-field verification: the form posts both `adminPassword` and
// `adminPasswordConfirm`. Client-side functions.js compares them on
// keystroke and only enables the submit button when they match;
// the server-side check below is defence in depth — never trust
// the client to enforce verification.
$passwordChanged  = false;
$passwordRejected = false;
$rejectReason     = '';
if (!empty($_POST['adminPassword'])) {
    $rawPassword        = stripslashes(trim($_POST['adminPassword']));
    $rawPasswordConfirm = isset($_POST['adminPasswordConfirm'])
        ? stripslashes(trim($_POST['adminPasswordConfirm']))
        : '';

    $hasIllegalChar = preg_match('/[\x00\r\n]/', $rawPassword);
    $tooLong        = strlen($rawPassword) > 256;
    $isStillDefault = hash_equals('raspberry', $rawPassword);
    // hash_equals on user-supplied vs user-supplied isn't a security
    // boundary (no secret on either side), but it's the right idiom
    // for password compares — and guards against any future caller
    // mistaking the result for an authentication signal.
    $confirmMatches = hash_equals($rawPassword, $rawPasswordConfirm);

    if ($rawPassword === '' || $hasIllegalChar || $tooLong) {
        $passwordRejected = true;
        $rejectReason     = 'invalid';
        error_log('Pi-Star change_password_required.php: adminPassword rejected '
                . '(empty, contains NUL/CR/LF, or > 256 bytes)');
    } elseif ($isStillDefault) {
        $passwordRejected = true;
        $rejectReason     = 'default';
        error_log('Pi-Star change_password_required.php: adminPassword rejected (still the default)');
    } elseif (!$confirmMatches) {
        $passwordRejected = true;
        $rejectReason     = 'mismatch';
        error_log('Pi-Star change_password_required.php: adminPassword rejected '
                . '(confirmation does not match)');
    } else {
        // Pi-Star runs with `/` mounted read-only by default. chpasswd
        // and htpasswd both write to files on the rootfs (/etc/shadow
        // and /var/www/.htpasswd respectively); without a remount-rw
        // they fail with PAM "Authentication token manipulation error"
        // and the symptom looks like every password is rejected. The
        // matching configure.php POST handler does this at line ~348.
        // Re-seal the rootfs at the bottom of this block on every
        // exit path (success, PAM rejection, htpasswd failure).
        system('sudo mount -o remount,rw /');

        $descriptors = array(
            0 => array('pipe', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),
        );

        // 1. Linux user via chpasswd. Hardcoded command; payload on stdin only.
        $cpExit = 1;
        $cpStderr = '';
        $proc = proc_open('sudo -n /usr/sbin/chpasswd', $descriptors, $pipes);
        if (is_resource($proc)) {
            fwrite($pipes[0], 'pi-star:' . $rawPassword . "\n");
            fclose($pipes[0]);
            stream_get_contents($pipes[1]); fclose($pipes[1]);
            $cpStderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
            $cpExit = proc_close($proc);
        } else {
            error_log('Pi-Star change_password_required.php: failed to spawn chpasswd');
        }

        if ($cpExit !== 0) {
            // PAM rejection (libpwquality, history, length, etc.).
            $passwordRejected = true;
            $rejectReason     = 'pam';
            error_log('Pi-Star change_password_required.php: chpasswd exit='
                    . $cpExit . '; stderr=' . trim($cpStderr));
        } else {
            // 2. Apache basic-auth file. /var/www/.htpasswd is owned by
            //    www-data, so no sudo needed.
            $htExit = 1;
            $htStderr = '';
            $proc = proc_open('htpasswd -i /var/www/.htpasswd pi-star',
                              $descriptors, $pipes);
            if (is_resource($proc)) {
                fwrite($pipes[0], $rawPassword);
                fclose($pipes[0]);
                stream_get_contents($pipes[1]); fclose($pipes[1]);
                $htStderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
                $htExit = proc_close($proc);
                if ($htExit !== 0) {
                    error_log('Pi-Star change_password_required.php: htpasswd exit='
                            . $htExit . ' (Linux password updated); stderr='
                            . trim($htStderr));
                }
            } else {
                error_log('Pi-Star change_password_required.php: failed to spawn htpasswd');
            }
            // chpasswd succeeded; treat as success even if htpasswd
            // failed (operator can retry — same behaviour as
            // configure.php). The browser will re-prompt for the new
            // credentials on the next request.
            $passwordChanged = true;
        }

        // Re-seal the rootfs on every exit path out of the writable
        // block. sync first so the shadow / htpasswd writes land on
        // disk before the remount makes the FS read-only again.
        system('sudo sync && sudo sync && sudo sync && sudo mount -o remount,ro /');
    }
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="Author" content="Andrew Taylor (MW0MWZ)" />
<meta name="Description" content="Pi-Star — Default password change required" />
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
<meta http-equiv="pragma" content="no-cache" />
<meta http-equiv="Expires" content="0" />
<link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon" />
<link rel="stylesheet" type="text/css" href="../css/pistar-css.php" />
<script type="text/javascript" src="/functions.js"></script>
<title>Pi-Star — Change Default Password</title>
</head>
<body>
<?php pistar_warnings_render(); ?>
<div class="container">
<div class="header">
  <h1>Pi-Star — Default Password Change Required</h1>
</div>
<div class="contentwide">
<?php if ($passwordChanged) { ?>
  <table>
    <tr><th>Working...</th></tr>
    <tr><td>Password changed. Your browser will re-prompt for the new credentials shortly.</td></tr>
  </table>
  <script type="text/javascript">setTimeout(function() { window.location='/admin/'; }, 5000);</script>
<?php } else { ?>
  <p>You are connecting from outside the local network and your dashboard is still using the
  factory default password. Set a new password to continue.</p>
<?php if ($passwordRejected) {
        // Distinct message per rejection class so the operator knows
        // exactly what to fix without having to guess.
        switch ($rejectReason) {
            case 'mismatch':
                $msg = '<b>Passwords do not match.</b> Please enter the same value in both fields.';
                break;
            case 'default':
                $msg = '<b>Password rejected.</b> The new password must be different from the factory default.';
                break;
            case 'pam':
                $msg = '<b>Password rejected by the system.</b> It must satisfy the system password-quality rules (length, complexity, history).';
                break;
            case 'invalid':
            default:
                $msg = '<b>Password rejected.</b> It must not contain NUL / CR / LF bytes and must be at most 256 bytes long.';
                break;
        }
?>
  <p style="color: #f01010;"><?php echo $msg; ?></p>
<?php } ?>
  <form id="adminPassForm" action="/admin/change_password_required.php" method="post" autocomplete="off">
    <?php echo csrf_field_html(); ?>
    <table>
      <tr>
        <td align="right" width="40%"><label for="pass1">New password:</label></td>
        <td align="left">
          <input type="password" name="adminPassword" id="pass1"
                 size="32" autocomplete="new-password"
                 onkeyup="checkPass(); return false;" required="required" />
        </td>
      </tr>
      <tr>
        <td align="right"><label for="pass2">Confirm password:</label></td>
        <td align="left">
          <input type="password" name="adminPasswordConfirm" id="pass2"
                 size="32" autocomplete="new-password"
                 onkeyup="checkPass(); return false;" required="required" />
        </td>
      </tr>
      <tr>
        <td colspan="2" align="center">
          <!-- id="submitpwd" matches the existing checkPass() in
               functions.js which enables this button only when both
               fields match. Server still re-verifies, so the JS gate
               is UX, not security. -->
          <input type="submit" id="submitpwd" value="Change Password" disabled="disabled" />
        </td>
      </tr>
    </table>
  </form>
<?php } ?>
</div>
<div class="footer">
Pi-Star / Pi-Star Dashboard, &copy; Andy Taylor (MW0MWZ) 2014-<?php echo date('Y'); ?>.<br />
</div>
</div>
</body>
</html>
