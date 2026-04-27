<?php
/**
 * Raw text editor for /etc/bmapi.key (BrandMeister API token).
 *
 * Creates the file on first save if it doesn't exist, using a sudo
 * shell-redirected `echo` (slight deviation from the standard
 * staged-write pattern). Used by mmdvmhost/bm_links.php and
 * mmdvmhost/bm_manager.php as the Bearer token for BrandMeister
 * API queries. No daemon restart.
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
// A3-3 — see edit_ircddbgateway.php for the full TOCTOU rationale.
// /etc/bmapi.key holds the BrandMeister API token, so the
// random-name TOCTOU defence is more important here than for the
// other editors. tempnam() creates the staging file mode 600
// owned by www-data with an unguessable random suffix.
$filepath = tempnam('/tmp', 'pistar-edit-');
register_shutdown_function(function() use ($filepath) { @unlink($filepath); });
if (file_exists('/etc/bmapi.key')) {
    exec('sudo cp /etc/bmapi.key ' . escapeshellarg($filepath));
} else {
    // Seed the staging file with the empty-config default. tempnam
    // already created the file owned by www-data, so PHP-side
    // file_put_contents writes through directly — no `sudo echo`
    // gymnastics needed.
    file_put_contents($filepath, "[key]\napikey=None\n");
}
exec('sudo chown www-data:www-data ' . escapeshellarg($filepath));
exec('sudo chmod 600 ' . escapeshellarg($filepath));

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

        //parse the ini file using default parse_ini_file() PHP function
        $parsed_ini = parse_ini_file($filepath, true);

        foreach($data as $section=>$values) {
            // UnBreak special cases
            $section = str_replace("_", " ", $section);
            $content .= "[".$section."]\n";
            //append the values
            foreach($values as $key=>$value) {
                // Strip CR/LF from values before they reach the INI
                // line. Same rationale as fulledit_dapnetapi.php: a
                // newline inside $value would split into a fresh
                // INI line and let an attacker inject extra keys.
                $value = str_replace(array("\r", "\n"), "", (string)$value);
                if ($value == '') {
          $content .= $key."=none\n";
        } else {
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

        // Atomic install: mode + owner set in one syscall sequence.
        // /etc/bmapi.key holds the BrandMeister API token — mode 600
        // keeps it readable only by www-data (the dashboard user).
        // Owner left as www-data because banner_warnings.inc / bm_links.php /
        // bm_manager.php read the file directly via parse_ini_file()
        // without sudo — switching to root:root here would silently
        // break those reads. (Tightening to root:root is a follow-up
        // once the read sites move to a sudo-cat helper.)
        exec('sudo mount -o remount,rw /');
        exec('sudo install -m 600 -o www-data -g www-data '
             . escapeshellarg($filepath) . ' /etc/bmapi.key');
        exec('sudo mount -o remount,ro /');

        return $success;
    }

//parse the ini file using default parse_ini_file() PHP function
$parsed_ini = parse_ini_file($filepath, true);
if (!isset($parsed_ini['key']['apikey'])) { $parsed_ini['key']['apikey'] = ""; }

echo '<form action="" method="post">'."\n";
echo csrf_field_html()."\n";
    foreach($parsed_ini as $section=>$values) {
        // INI section / key / value all come from /etc/bmapi.key. Same
        // hardening as edit_mmdvmhost.php (#23) but the value lands
        // inside a <textarea>...</textarea> body — htmlspecialchars
        // covers both attribute and body contexts safely. Browser
        // decodes the named entities on form submit, so legitimate
        // values containing `<`, `>`, `&`, `"` round-trip byte-identically.
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
                echo "<tr><td align=\"right\" width=\"30%\">$keyHtml</td><td align=\"left\"><textarea name=\"{$sectionHtml}[$keyHtml]\" cols=\"60\" rows=\"13\">$valueHtml</textarea></td></tr>\n";
            }
            elseif (($key == "Display") && ($value == '')) {
                echo "<tr><td align=\"right\" width=\"30%\">$keyHtml</td><td align=\"left\"><textarea name=\"{$sectionHtml}[$keyHtml]\" cols=\"60\" rows=\"13\">$valueHtml</textarea></td></tr>\n";
            }
            else {
                echo "<tr><td align=\"right\" width=\"30%\">$keyHtml</td><td align=\"left\"><textarea name=\"{$sectionHtml}[$keyHtml]\" cols=\"60\" rows=\"13\">$valueHtml</textarea></td></tr>\n";
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

