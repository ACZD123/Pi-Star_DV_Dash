<?php
/**
 * Raw text editor for /usr/local/etc/RSSI.dat.
 *
 * The modem RSSI calibration table — non-/etc location, edited the
 * same way as the other fulledit_* files. No daemon restart (MMDVMHost
 * re-reads RSSI.dat on its own).
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
if(isset($_POST['data'])) {
        // File Wrangling
        exec('sudo cp /usr/local/etc/RSSI.dat /tmp/yAw432GHs5.tmp');
        exec('sudo chown www-data:www-data /tmp/yAw432GHs5.tmp');
        exec('sudo chmod 600 /tmp/yAw432GHs5.tmp');

        // Open the file and write the data
        $filepath = '/tmp/yAw432GHs5.tmp';
        // Clean up the /tmp staging file on script exit so the
        // editor's potentially-secrets-bearing copy of /etc/<config>
        // doesn't persist between requests. @-suppression handles
        // the case where a sudo mv (e.g. fulledit_bmapikey) already
        // consumed the staging file before script end.
        register_shutdown_function(function() use ($filepath) { @unlink($filepath); });
        $fh = fopen($filepath, 'w');
        fwrite($fh, $_POST['data']);
        fclose($fh);
        // Atomic install: content + mode + owner set in one syscall
        // sequence. Same rationale as the bmapikey/dapnetapi B5 work
        // and the parallel pistar-remote / pistar-css.ini migrations.
        // /usr/local/etc/RSSI.dat is read by the MMDVMHost daemon
        // (root) and is world-readable for the dashboard's editor
        // round-trip; 644 root:root preserves both.
        exec('sudo mount -o remount,rw /');
        exec('sudo install -m 644 -o root -g root /tmp/yAw432GHs5.tmp /usr/local/etc/RSSI.dat');
        exec('sudo mount -o remount,ro /');

        // Re-open the file and read it
        $fh = fopen($filepath, 'r');
        $theData = fread($fh, filesize($filepath));

} else {
        // File Wrangling
        exec('sudo cp /usr/local/etc/RSSI.dat /tmp/yAw432GHs5.tmp');
        exec('sudo chown www-data:www-data /tmp/yAw432GHs5.tmp');
        exec('sudo chmod 600 /tmp/yAw432GHs5.tmp');

        // Open the file and read it
        $filepath = '/tmp/yAw432GHs5.tmp';
        // Clean up the /tmp staging file on script exit so the
        // editor's potentially-secrets-bearing copy of /etc/<config>
        // doesn't persist between requests. @-suppression handles
        // the case where a sudo mv (e.g. fulledit_bmapikey) already
        // consumed the staging file before script end.
        register_shutdown_function(function() use ($filepath) { @unlink($filepath); });
        $fh = fopen($filepath, 'r');
        $theData = fread($fh, filesize($filepath));
}
fclose($fh);

?>
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

