<?php
/**
 * Expert editor for /etc/pistar-css.ini — the dashboard theme overrides.
 *
 * Same staged-write pattern as the other edit_*.php files except no
 * daemon restart is needed (CSS is loaded fresh on the next page hit).
 * Provides a 'Reset to defaults' path that does a `sudo rm -rf` on
 * /etc/pistar-css.ini inside the mount-rw window — guarded only by a
 * JS confirm() prompt; flag for the security pass.
 *
 * Output of this editor is consumed by css/pistar-css.php,
 * css/pistar-css-mini.php, and admin/wifi/styles.php — the three CSS
 * emitters that read from /etc/pistar-css.ini.
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
    <script type="text/javascript">
      function factoryReset()
      {
        // Typed confirmation. The server-side handler requires
        // factoryResetConfirm === 'RESET' before performing the
        // wipe — so a misclicked button or an accidental form
        // replay does NOT reset the dashboard CSS, even though
        // the CSRF token is otherwise valid.
        var typed = prompt(
            'WARNING: This will reset these settings to factory defaults.\n\n'
          + 'Type RESET (uppercase) and press OK to proceed.\n'
          + 'Press Cancel to go back.', '');
        if (typed === null) { return false; }     // Cancel
        if (typed !== 'RESET') {
            alert('Confirmation text did not match. Factory reset cancelled.');
            return false;
        }
        document.getElementById('factoryResetConfirmInput').value = typed;
        document.getElementById('factoryReset').submit();
      }
    </script>
  </head>
  <body>
  <?php pistar_warnings_render(); ?>
  <div class="container">
  <?php include './header-menu.inc'; ?>
  <div class="contentwide">

<?php
if (!file_exists('/etc/pistar-css.ini')) {
    //The source file does not exist, lets create it....
    $outFile = fopen("/tmp/bW1kd4jg6b3N0DQo.tmp", "w") or die("Unable to open file!");
    $fileContent = "[Background]\nPage=edf0f5\nContent=ffffff\nBanners=dd4b39\n\n";
    $fileContent .= "[Text]\nBanners=ffffff\nBannersDrop=303030\n\n";
    $fileContent .= "[Tables]\nHeadDrop=8b0000\nBgEven=f7f7f7\nBgOdd=d0d0d0\n\n";
    $fileContent .= "[Content]\nText=000000\n\n";
    $fileContent .= "[BannerH1]\nEnabled=0\nText=\"Some Text\"\n\n";
    $fileContent .= "[BannerExtText]\nEnabled=0\nText=\"Some long text entry\"\n\n";
    $fileContent .= "[Lookup]\nService=\"RadioID\"\n";
    fwrite($outFile, $fileContent);
    fclose($outFile);

    // Put the file back where it should be
    exec('sudo mount -o remount,rw /');                             // Make rootfs writable
    exec('sudo cp /tmp/bW1kd4jg6b3N0DQo.tmp /etc/pistar-css.ini');  // Move the file back
    exec('sudo chmod 644 /etc/pistar-css.ini');                     // Set the correct runtime permissions
    exec('sudo chown root:root /etc/pistar-css.ini');               // Set the owner
    exec('sudo mount -o remount,ro /');                             // Make rootfs read-only
}

//Do some file wrangling...
exec('sudo cp /etc/pistar-css.ini /tmp/bW1kd4jg6b3N0DQo.tmp');
exec('sudo chown www-data:www-data /tmp/bW1kd4jg6b3N0DQo.tmp');
exec('sudo chmod 600 /tmp/bW1kd4jg6b3N0DQo.tmp');

//ini file to open
$filepath = '/tmp/bW1kd4jg6b3N0DQo.tmp';
// Clean up the /tmp staging file on script exit so the
// editor's potentially-secrets-bearing copy of /etc/<config>
// doesn't persist between requests. @-suppression handles
// the case where a sudo mv (e.g. fulledit_bmapikey) already
// consumed the staging file before script end.
register_shutdown_function(function() use ($filepath) { @unlink($filepath); });

//after the form submit
if($_POST) {
    $data = $_POST;
    // Factory Reset Handler Here
    if (empty($_POST['factoryReset']) != TRUE ) {
        // Server-side confirmation gate. The form ships a hidden
        // factoryResetConfirm input that the JS factoryReset()
        // populates only after the operator types `RESET` into
        // the prompt. Comparing strictly to the magic string
        // (===) means a misclicked button, a replayed POST, or
        // a curl with just `factoryReset=1` does NOT trigger the
        // wipe — even with a valid CSRF token.
        $confirm = isset($_POST['factoryResetConfirm']) ? $_POST['factoryResetConfirm'] : '';
        if ($confirm !== 'RESET') {
            echo "<br />\n";
            echo "<table>\n";
            echo "<tr><th>Factory Reset NOT performed</th></tr>\n";
            echo "<tr><td>Server-side confirmation did not match. Factory reset cancelled.</td><tr>\n";
            echo "</table>\n";
            unset($_POST);
        } else {
            echo "<br />\n";
            echo "<table>\n";
            echo "<tr><th>Factory Reset Config</th></tr>\n";
            echo "<tr><td>Loading fresh configuration file(s)...</td><tr>\n";
            echo "</table>\n";
            unset($_POST);
            //Reset the config
            exec('sudo mount -o remount,rw /');                             // Make rootfs writable
            exec('sudo rm -rf /etc/pistar-css.ini');                        // Delete the Config
            exec('sudo mount -o remount,ro /');                             // Make rootfs read-only
            echo '<script type="text/javascript">setTimeout(function() { window.location=window.location;},0);</script>';
            die();
        }
    } else {
        //update ini file, call function
        update_ini_file($data, $filepath);
    }
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
            $section = str_replace("BannerH2", "BannerH1", $section);
            $content .= "[".$section."]\n";
            //append the values
            foreach($values as $key=>$value) {
                if ($value == '') {
                    $content .= $key."=none\n";
                }
                else {
                    $content .= $key."=".$value."\n";
                }
            }
            $content .= "\n";
        }

        //write it into file
        if (!$handle = fopen($filepath, 'w')) {
            return false;
        }

        $success = fwrite($handle, $content);
        fclose($handle);

        // Updates complete - copy the working file back to the proper location
        exec('sudo mount -o remount,rw /');                             // Make rootfs writable
        exec('sudo cp /tmp/bW1kd4jg6b3N0DQo.tmp /etc/pistar-css.ini');  // Move the file back
        exec('sudo chmod 644 /etc/pistar-css.ini');                     // Set the correct runtime permissions
        exec('sudo chown root:root /etc/pistar-css.ini');               // Set the owner
        exec('sudo mount -o remount,ro /');                             // Make rootfs read-only

        return $success;
    }

//parse the ini file using default parse_ini_file() PHP function
$parsed_ini = parse_ini_file($filepath, true);
if (isset($parsed_ini['Lookup']['popupWidth']))  { unset($parsed_ini['Lookup']['popupWidth']); }
if (isset($parsed_ini['Lookup']['popupHeight'])) { unset($parsed_ini['Lookup']['popupHeight']); }

echo '<form action="" method="post">'."\n";
echo csrf_field_html()."\n";
    foreach($parsed_ini as $section=>$values) {
        // Same hardening as edit_mmdvmhost.php (#23): escape every
        // INI section / key / value before HTML interpolation. The
        // save handler writes POST bytes verbatim so legitimate
        // values (including any with `"` or `<`) round-trip
        // byte-identically.
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
          if ( $section == "Lookup" && $key == "Service" ) {
            echo "<tr><td align=\"right\" width=\"30%\">$keyHtml</td><td align=\"left\">\n";
            echo "  <select name=\"{$sectionHtml}[$keyHtml]\" />\n";
            if ($value == "RadioID") {
              echo "    <option value=\"RadioID\" selected=\"selected\">RadioID Callsign Lookup</option>\n";
            } else {
              echo "    <option value=\"RadioID\">RadioID Callsign Lookup</option>\n";
            }
            if ($value == "QRZ") {
              echo "    <option value=\"QRZ\" selected=\"selected\">QRZ Callsign Lookup</option>\n";
            } else {
              echo "    <option value=\"QRZ\">QRZ Callsign Lookup</option>\n";
            }
            echo "  </select>\n";
            echo "</td></tr>\n";
          } else {
            echo "<tr><td align=\"right\" width=\"30%\">$keyHtml</td><td align=\"left\"><input type=\"text\" name=\"{$sectionHtml}[$keyHtml]\" value=\"$valueHtml\" /></td></tr>\n";
          }
        }
        echo "</table>\n";
        echo '<input type="submit" value="'.$lang['apply'].'" />'."\n";
        echo "<br /><br />\n";
    }
echo "</form>";
echo "<br />\n";
echo 'if you took it all too far and now it makes you feel sick, click below to reset the changes made on this page, this will ONLY reset the CSS settings above and will not change any other settings or configuration.'."\n";
echo '<form id="factoryReset" action="" method="post">'."\n";
echo csrf_field_html()."\n";
echo '  <div><input type="hidden" name="factoryReset" value="1" /></div>'."\n";
// Server-side confirmation. JS factoryReset() prompts for the
// magic word and only populates this input on a match. The
// handler requires factoryResetConfirm === 'RESET' before doing
// the wipe — closes the "valid CSRF token + accidental replay"
// attack class.
echo '  <div><input type="hidden" id="factoryResetConfirmInput" name="factoryResetConfirm" value="" /></div>'."\n";
echo '</form>'."\n";
echo '<input type="button" onclick="javascript:factoryReset();" value="'.$lang['factory_reset'].'" />'."\n";
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

