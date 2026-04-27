<?php
/**
 * Expert INI editor for /etc/ysfgateway.
 *
 * Renders a per-section / per-key form built from parse_ini_file()
 * output, accepts edits via POST, then writes the result back to
 * /etc/ysfgateway using the standard Pi-Star copy-via-/tmp pattern:
 *   1. sudo cp /etc/ysfgateway /tmp/<obfuscated>.tmp + chown www-data
 *      + chmod 664 (so PHP can edit the temp).
 *   2. fopen('w') and fwrite the rebuilt INI text into the temp.
 *   3. sudo mount -o remount,rw / + sudo cp temp -> /etc/ysfgateway
 *      + sudo chmod 644 + sudo chown root:root + sudo mount -o
 *      remount,ro / to seal the rootfs again.
 *   4. sudo systemctl restart ysfgateway.service to pick up the change.
 *
 * Admin-only access; the dashboard's Apache basic-auth gate is the
 * sole protection. The validation is what's in the form (none, in
 * effect — operator-typed values are written raw). Treat with care.
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
  <div class="container">
  <?php include './header-menu.inc'; ?>
  <div class="contentwide">

<?php
// Do some file wrangling...
exec('sudo cp /etc/ysfgateway /tmp/eXNmZ2F0ZXdheQ.tmp');
exec('sudo chown www-data:www-data /tmp/eXNmZ2F0ZXdheQ.tmp');
exec('sudo chmod 664 /tmp/eXNmZ2F0ZXdheQ.tmp');

// ini file to open
$filepath = '/tmp/eXNmZ2F0ZXdheQ.tmp';

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
            if (strpos($section, 'aprs') !== false) { $section = str_replace("_", ".", $section); }
            else { $section = str_replace("_", " ", $section); $section = str_replace(".", " ", $section); }
            $content .= "[".$section."]\n";
            //append the values
            foreach($values as $key=>$value) {
                $content .= $key."=".$value."\n";
            }
            $content .= "\n";
        }

        // write it into file
        if (!$handle = fopen($filepath, 'w')) {
            return false;
        }

        $success = fwrite($handle, $content);
        fclose($handle);

        // Updates complete - copy the working file back to the proper location
        exec('sudo mount -o remount,rw /');                // Make rootfs writable
        exec('sudo cp /tmp/eXNmZ2F0ZXdheQ.tmp /etc/ysfgateway');    // Move the file back
        exec('sudo chmod 644 /etc/ysfgateway');                // Set the correct runtime permissions
        exec('sudo chown root:root /etc/ysfgateway');            // Set the owner
        exec('sudo mount -o remount,ro /');                // Make rootfs read-only

        // Reload the affected daemon
        exec('sudo systemctl restart ysfgateway.service');        // Reload the daemon
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

