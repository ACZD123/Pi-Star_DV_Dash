<?php
/**
 * Expert editor for /etc/ircddbgateway (D-Star side gateway config).
 *
 * Same flat key=value file as /etc/dstarrepeater — uses the synthetic
 * `[ircddbgateway]` section header trick on read and sed-strip on
 * write so parse_ini_file() can handle it. Standard Pi-Star
 * copy-via-/tmp / mount-rw / restart pattern; daemon:
 * ircddbgateway.service.
 */
require_once($_SERVER['DOCUMENT_ROOT'].'/config/security_headers.php');
require_once($_SERVER['DOCUMENT_ROOT'].'/config/csrf.php');
require_once($_SERVER['DOCUMENT_ROOT'].'/config/banner_warnings.inc');
setSecurityHeaders();

// CSRF protection — see config/csrf.php for the full rationale.
// Must run BEFORE any output: bootstraps the session on GET (so
// Set-Cookie ships) and rejects forged POSTs cleanly with 403
// before any state change (sed-i, fopen+fwrite, sudo cp, etc.).
csrf_verify();

// Layer 2 of the default-password protection — see config/banner_warnings.inc.
// MUST run BEFORE any output so header('Location: ...') works.
pistar_warnings_enforce_redirect();

// Load the language support
require_once('../config/language.php');
//Load the Pi-Star Release file
$pistarReleaseConfig = '/etc/pistar-release';
$configPistarRelease = array();
$configPistarRelease = parse_ini_file($pistarReleaseConfig, true);
//Load the Version Info
require_once('../config/version.php');
?>
  <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
  <html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" lang="en">
  <head>
    <meta name="robots" content="index" />
    <meta name="robots" content="follow" />
    <meta name="language" content="English" />
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
    <meta name="Author" content="Andrew Taylor (MW0MWZ)" />
    <meta name="Description" content="Pi-Star Expert Editor" />
    <meta name="KeyWords" content="Pi-Star" />
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
    <meta http-equiv="pragma" content="no-cache" />
<link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon">
    <meta http-equiv="Expires" content="0" />
    <title>Pi-Star - Digital Voice Dashboard - Expert Editor</title>
    <link rel="stylesheet" type="text/css" href="../css/pistar-css.php" />
  </head>
  <body>
  <?php pistar_warnings_render(); ?>
  <div class="container">
  <?php include './header-menu.inc'; ?>
  <div class="contentwide">

<?php
// Stage a copy of /etc/ircddbgateway in /tmp under a random,
// per-request name (A3-3). tempnam() creates the file mode 600
// owned by the calling PHP-FPM user (www-data); the unguessable
// suffix defeats the predictable-name TOCTOU class — an attacker
// who knew the path could otherwise pre-create it as a symlink
// to /etc/shadow or similar and have our `sudo cp` follow the
// link and overwrite the target. Cleanup is registered up front
// so the staging copy never persists past script exit, even on a
// die() / fatal-error path. @-suppression handles the case where
// a sudo mv path consumed the file before script end.
$filepath = tempnam('/tmp', 'pistar-edit-');
register_shutdown_function(function() use ($filepath) { @unlink($filepath); });
exec('sudo cp /etc/ircddbgateway ' . escapeshellarg($filepath));
// Defensively re-assert mode + owner. tempnam already created
// the file 600 www-data, and `sudo cp` against an existing
// regular file truncates-in-place (mode/owner preserved); these
// remain as belt-and-braces to match the surrounding pattern.
exec('sudo chown www-data:www-data ' . escapeshellarg($filepath));
exec('sudo chmod 600 ' . escapeshellarg($filepath));

// Mangle the input
$file_content = "[ircddbgateway]\n".preg_replace('~\r\n?~', "\n", file_get_contents($filepath));
file_put_contents($filepath, $file_content);

// after the form submit
if($_POST) {
    $data = $_POST;
    //update ini file, call function
    update_ini_file($data, $filepath);
}

// this is the function going to update your ini file
    function update_ini_file($data, $filepath)
    {
        $content = "";

        // parse the ini file to get the sections
        // parse the ini file using default parse_ini_file() PHP function
        $parsed_ini = parse_ini_file($filepath, true);

        foreach($data as $section=>$values) {
                        // UnBreak special cases
                        $section = str_replace("_", " ", $section);
                        $content .= "[".$section."]\n";
            //append the values
            foreach($values as $key=>$value) {
                if ($value == '') {
                    $content .= $key."= \n";
                    }
                else {
                    $content .= $key."=".$value."\n";
                    }
            }
        }

        // write it into file
        if (!$handle = fopen($filepath, 'w')) {
            return false;
        }

        $success = fwrite($handle, $content);
        fclose($handle);

        // /etc/ircddbgateway is a FLAT key=value file on disk — the
        // synthetic [ircddbgateway] header was injected at line ~75
        // only to satisfy parse_ini_file()'s section model. The /tmp
        // staging file keeps the header (so the form re-render via
        // parse_ini_file at the bottom of this script still finds
        // sections); the on-disk version must not. Strip via PHP's
        // preg_replace and install the cleaned content directly —
        // drops the prior `sudo sed -i` from this code path (L-7).
        $etcContent  = preg_replace('/^\[ircddbgateway\]\r?\n/m', '', $content);
        // A3-3: per-request random staging file rather than a
        // predictable hardcoded /tmp/<obf>.tmp path. tempnam() also
        // creates the file mode 600 — and since this is a freshly
        // created file (not yet referenced anywhere), there's no
        // race for an attacker to swap in a symlink before our write.
        $etcStaging  = tempnam('/tmp', 'pistar-edit-etc-');
        file_put_contents($etcStaging, $etcContent);

        // Atomic install: content + mode + owner set in one syscall
        // sequence (B5 / L-5 pattern). Replaces the prior cp +
        // chmod + chown trio so an interrupted RW window can't leave
        // /etc/ircddbgateway in a transient state.
        exec('sudo mount -o remount,rw /');
        exec('sudo install -m 644 -o root -g root '
             . escapeshellarg($etcStaging) . ' /etc/ircddbgateway');
        exec('sudo mount -o remount,ro /');
        @unlink($etcStaging);

        // Reload the affected daemon
        exec('sudo systemctl restart ircddbgateway.service');            // Reload the daemon
        return $success;
    }

// parse the ini file using default parse_ini_file() PHP function
$parsed_ini = parse_ini_file($filepath, true);

echo '<form action="" method="post">'."\n";
echo csrf_field_html()."\n";
    foreach($parsed_ini as $section=>$values) {
        // keep the section as hidden text so we can update once the form submitted
        // INI section / key / value all come from the underlying
        // /etc/<gateway> file. Same hardening as edit_mmdvmhost.php
        // (#23): htmlspecialchars(ENT_QUOTES) on display so a value
        // with a literal `"` or `<` (e.g. an Options string) can't
        // break out of the `value="…"` attribute. The save handler
        // writes the POST bytes verbatim, so legitimate quoted
        // values round-trip byte-identically.
        $sectionHtml = htmlspecialchars((string)$section, ENT_QUOTES, 'UTF-8');
        echo "<input type=\"hidden\" value=\"$sectionHtml\" name=\"$sectionHtml\" />\n";
        echo "<table>\n";
        echo "<tr><th colspan=\"2\">$sectionHtml</th></tr>\n";
        // print all other values as input fields, so can edit.
        // note the name='' attribute it has both section and key
        foreach($values as $key=>$value) {
            $keyHtml   = htmlspecialchars((string)$key, ENT_QUOTES, 'UTF-8');
            $valueHtml = htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
            echo "<tr><td align=\"right\" width=\"30%\">$keyHtml</td><td align=\"left\"><input type=\"text\" name=\"{$sectionHtml}[$keyHtml]\" value=\"$valueHtml\" /></td></tr>\n";
        }
        echo "</table>\n";
        echo '<input type="submit" value="'.$lang['apply'].'" />'."\n";
        echo "<br />\n";
    }
echo "</form>";
?>
</div>

<div class="footer">
Pi-Star / Pi-Star Dashboard, &copy; Andy Taylor (MW0MWZ) 2014-<?php echo date("Y"); ?>.<br />
Need help? Click <a style="color: #ffffff;" href="https://www.facebook.com/groups/pistarusergroup/" target="_new">here for the Support Group</a><br />
Get your copy of Pi-Star from <a style="color: #ffffff;" href="http://www.pistar.uk/downloads/" target="_new">here</a>.<br />
</div>

</div>
</body>
</html>

