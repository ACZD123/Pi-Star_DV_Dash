<?php
/**
 * ShellInABox iframe wrapper.
 *
 * Reads the configured shellinabox port from /etc/default/shellinabox
 * and embeds the in-browser SSH terminal as an <iframe>. Uses
 * setSecurityHeadersAllowDifferentPorts() to relax the default same-
 * origin frame restriction so the iframe can target a non-80 port on
 * the same host.
 *
 * No file edits, no privileged calls — pure UI wrapper.
 */
require_once($_SERVER['DOCUMENT_ROOT'].'/config/security_headers.php');
setSecurityHeadersAllowDifferentPorts();

// Load the language support
require_once('../config/language.php');
// Load the Pi-Star Release file
$pistarReleaseConfig = '/etc/pistar-release';
$configPistarRelease = array();
$configPistarRelease = parse_ini_file($pistarReleaseConfig, true);
// Load the Version Info
require_once('../config/version.php');

if (file_exists('/etc/default/shellinabox')) {
  $getPortCommand = "grep -m 1 'SHELLINABOX_PORT=' /etc/default/shellinabox | awk -F '=' '/SHELLINABOX_PORT=/ {print $2}'";
  $shellPort = exec($getPortCommand);
}

// HTTP_HOST is client-controllable (any HTTP client can send any
// `Host:` header). Echoing it raw into HTML attributes — as the
// iframe `src` and the anchor `href` below do — gives a passing
// attacker a reflected XSS surface: a request with a crafted Host
// header would render an iframe pointing at attacker-controlled
// content inside this page.
//
// Two-layer defence:
//   1. Strip everything that isn't a hostname character. The set
//      `[a-zA-Z0-9.\-\[\]:]` covers DNS names, IPv4 dotted-quad,
//      IPv6 bracketed literals, and the optional `:port` suffix.
//      Anything else (CRLF, `<`, `"`, `'`, semicolons, spaces,
//      parens, slashes) is dropped — the regex is what closes
//      the XSS / response-splitting class.
//   2. htmlspecialchars on top, so even if the regex were
//      relaxed in the future the value still can't break out
//      of the `"…"` HTML attribute it lands in.
$shellHost = preg_replace(
    '/[^a-zA-Z0-9.\-\[\]:]/',
    '',
    isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : ''
);
if ($shellHost === '') {
    // Pathological case: HTTP_HOST contained nothing usable. Fall
    // back to the LAN IP that nginx listens on rather than emitting
    // a broken iframe `src=":port"`.
    $shellHost = 'localhost';
}
$shellHostHtml = htmlspecialchars($shellHost, ENT_QUOTES, 'UTF-8');
$shellPortHtml = htmlspecialchars((string)(isset($shellPort) ? $shellPort : ''), ENT_QUOTES, 'UTF-8');

// Sanity Check that this file has been opened correctly
if ($_SERVER["PHP_SELF"] == "/admin/expert/ssh_access.php") {
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
    <meta name="Description" content="Pi-Star Update" />
    <meta name="KeyWords" content="Pi-Star" />
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
    <meta http-equiv="pragma" content="no-cache" />
<link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon">
    <meta http-equiv="Expires" content="0" />
    <title>Pi-Star - <?php echo $lang['digital_voice']." ".$lang['dashboard']." - SSH";?></title>
    <link rel="stylesheet" type="text/css" href="../css/pistar-css.php" />
    <script type="text/javascript" src="/jquery.min.js"></script>
    <script type="text/javascript" src="/jquery-timing.min.js"></script>
  </head>
  <body>
  <div class="container">
  <?php include './header-menu.inc'; ?>
  <div class="contentwide">
  <table width="100%">
  <tr><th>SSH - Pi-Star</th></tr>
  <tr><td align="left"><div id="tail">
    <?php if (isset($shellPort)) {
      echo "<iframe src=\"http://" . $shellHostHtml . ":" . $shellPortHtml . "\" style=\"border:0px #ffffff none; background:#ffffff; color:#00ff00;\" name=\"Pi-Star_SSH\" scrolling=\"no\" frameborder=\"0\" marginheight=\"0px\" marginwidth=\"0px\" height=\"100%\" width=\"100%\"></iframe>";
    }
    else {
      echo "SSH Feature not yet installed";
    } ?>
  </div></td></tr>
  </table>
  <?php if (isset($shellPort)) { echo "<a href=\"//" . $shellHostHtml . ":" . $shellPortHtml . "\">Click here for fullscreen SSH client</a><br />\n"; } ?>
  </div>
  <div class="footer">
  Pi-Star web config, &copy; Andy Taylor (MW0MWZ) 2014-<?php echo date("Y"); ?>.<br />
  Need help? Click <a style="color: #ffffff;" href="https://www.facebook.com/groups/pistarusergroup/" target="_new">here for the Support Group</a><br />
  Get your copy of Pi-Star from <a style="color: #ffffff;" href="http://www.pistar.uk/downloads/" target="_blank">here</a>.<br />
  <br />
  </div>
  </div>
  </body>
  </html>

<?php
}
