<?php
/**
 * Raw text editor for /etc/dapnetapi.key (DAPNET credentials).
 *
 * Same first-save-via-shell-echo pattern as fulledit_bmapikey.php.
 * Read by dapnetgateway at startup; no daemon restart from this
 * editor.
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
// Make the bare config if we dont have one
if (file_exists('/etc/dapnetapi.key')) {
    exec('sudo cp /etc/dapnetapi.key /tmp/jsADGHwf9sj294.tmp');
    exec('sudo chown www-data:www-data /tmp/jsADGHwf9sj294.tmp');
} else {
    exec('sudo touch /tmp/jsADGHwf9sj294.tmp');
    exec('sudo chown www-data:www-data /tmp/jsADGHwf9sj294.tmp');
    exec('echo "[DAPNETAPI]" > /tmp/jsADGHwf9sj294.tmp');
    exec('echo "USER=" >> /tmp/jsADGHwf9sj294.tmp');
    exec('echo "PASS=" >> /tmp/jsADGHwf9sj294.tmp');
    exec('echo "TRXAREA=" >> /tmp/jsADGHwf9sj294.tmp');
}

//Do some file wrangling...
exec('sudo chmod 600 /tmp/jsADGHwf9sj294.tmp');

//ini file to open
$filepath = '/tmp/jsADGHwf9sj294.tmp';
// Clean up the /tmp staging file on script exit so the
// editor's potentially-secrets-bearing copy of /etc/<config>
// doesn't persist between requests. @-suppression handles
// the case where a sudo mv (e.g. fulledit_bmapikey) already
// consumed the staging file before script end.
register_shutdown_function(function() use ($filepath) { @unlink($filepath); });

//after the form submit
if($_POST) {
    $data = $_POST;
    //update ini file, call function
    update_ini_file($data, $filepath);
}

//this is the function going to update your ini file
    function update_ini_file($data, $filepath)
    {
        $content = "";

        //parse the ini file to get the sections
        //parse the ini file using default parse_ini_file() PHP function
        $parsed_ini = parse_ini_file($filepath, true);

        foreach($data as $section=>$values) {
            // UnBreak special cases
            $section = str_replace("_", " ", $section);
            $content .= "[".$section."]\n";
            //append the values
            foreach($values as $key=>$value) {
                // Strip CR/LF from values before they land in the INI
                // file. The save handler writes `$key=$value\n` and a
                // newline inside $value would split the value into a
                // new INI line, allowing injection of arbitrary
                // additional keys (e.g. `value=foo\nDEBUG=1`). On a
                // single-operator device the practical risk is low
                // but the sanitiser is one line.
                $value = str_replace(array("\r", "\n"), "", (string)$value);
                $content .= $key."=".$value."\n";
            }
            $content .= "\n";
        }

        //write it into file
        if (!$handle = fopen($filepath, 'w')) {
            return false;
        }

        $success = fwrite($handle, $content);
        fclose($handle);

        // Atomic install: mode + owner set in one syscall sequence.
        // /etc/dapnetapi.key holds DAPNET credentials — mode 600 keeps
        // them readable only by www-data. Owner left as www-data
        // because the dapnetgateway daemon reads via the dashboard
        // (and dashboard reads it directly without sudo elsewhere);
        // see fulledit_bmapikey.php for the same rationale.
        exec('sudo mount -o remount,rw /');
        exec('sudo install -m 600 -o www-data -g www-data /tmp/jsADGHwf9sj294.tmp /etc/dapnetapi.key');
        exec('sudo mount -o remount,ro /');

        return $success;
    }

//parse the ini file using default parse_ini_file() PHP function
$parsed_ini = parse_ini_file($filepath, true);

echo '<form action="" method="post">'."\n";
echo csrf_field_html()."\n";
    foreach($parsed_ini as $section=>$values) {
        // Same hardening as edit_mmdvmhost.php (#23): escape every INI
        // section / key / value before HTML interpolation. The save
        // handler writes POST bytes verbatim so legitimate values
        // (including any with `"` or `<`) round-trip byte-identically.
        $sectionHtml = htmlspecialchars((string)$section, ENT_QUOTES, 'UTF-8');
        // keep the section as hidden text so we can update once the form submitted
        echo "<input type=\"hidden\" value=\"$sectionHtml\" name=\"$sectionHtml\" />\n";
        echo "<table>\n";
        echo "<tr><th colspan=\"2\">$sectionHtml</th></tr>\n";
        // print all other values as input fields, so can edit.
        // note the name='' attribute it has both section and key
        foreach($values as $key=>$value) {
            $keyHtml   = htmlspecialchars((string)$key, ENT_QUOTES, 'UTF-8');
            $valueHtml = htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
            if (($key == "Options") || ($value)) {
                echo "<tr><td align=\"right\" width=\"30%\">$keyHtml</td><td align=\"left\"><input type=\"text\" name=\"{$sectionHtml}[$keyHtml]\" value=\"$valueHtml\" /></td></tr>\n";
            }
            elseif (($key == "Display") && ($value == '')) {
                echo "<tr><td align=\"right\" width=\"30%\">$keyHtml</td><td align=\"left\"><input type=\"text\" name=\"{$sectionHtml}[$keyHtml]\" value=\"None\" /></td></tr>\n";
            }
            else {
                echo "<tr><td align=\"right\" width=\"30%\">$keyHtml</td><td align=\"left\"><input type=\"text\" name=\"{$sectionHtml}[$keyHtml]\" value=\"0\" /></td></tr>\n";
            }
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

