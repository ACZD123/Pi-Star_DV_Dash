<?php
/**
 * Raw text editor for /etc/wpa_supplicant/wpa_supplicant.conf.
 *
 * Operator-editable WiFi configuration. Standard staged-write pattern.
 *
 * No daemon restart from this file; the operator must reset the WiFi
 * adapter (admin/wifi.php has buttons) for changes to take effect.
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
        exec('sudo cp /etc/wpa_supplicant/wpa_supplicant.conf /tmp/k45s7h5s9k3.tmp');
        exec('sudo chown www-data:www-data /tmp/k45s7h5s9k3.tmp');
        exec('sudo chmod 664 /tmp/k45s7h5s9k3.tmp');

        // Open the file and write the data
        $filepath = '/tmp/k45s7h5s9k3.tmp';
        $fh = fopen($filepath, 'w');
        fwrite($fh, $_POST['data']);
        fclose($fh);
        exec('sudo mount -o remount,rw /');
        // Atomic install: mode + owner set in one syscall sequence.
        // wpa_supplicant.conf carries the WPA PSK in cleartext as
        // `psk=…hex…` — mode 600 root:root keeps every other local
        // user (and any sandbox-escape from another service) from
        // reading it. wpa_supplicant runs as root, so the daemon's
        // own access is unaffected.
        exec('sudo install -m 600 -o root -g root /tmp/k45s7h5s9k3.tmp /etc/wpa_supplicant/wpa_supplicant.conf');
        exec('sudo mount -o remount,ro /');

        // Re-open the file and read it
        $fh = fopen($filepath, 'r');
        $theData = fread($fh, filesize($filepath));

} else {
        // File Wrangling
        exec('sudo cp /etc/wpa_supplicant/wpa_supplicant.conf /tmp/k45s7h5s9k3.tmp');
        exec('sudo chown www-data:www-data /tmp/k45s7h5s9k3.tmp');
        exec('sudo chmod 664 /tmp/k45s7h5s9k3.tmp');

        // Open the file and read it
        $filepath = '/tmp/k45s7h5s9k3.tmp';
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

