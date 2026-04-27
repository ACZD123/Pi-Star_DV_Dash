<?php
/**
 * WiFi configuration page.
 *
 * Two query-string-driven views:
 *   ?page=wlan0_info  — interface stats: IP/netmask, packet/byte
 *                        counters, SSID/BSSID, bitrate, signal,
 *                        channel, regulatory domain. Parsed from
 *                        ifconfig + iwconfig + iw output via lots of
 *                        regex.
 *   ?page=wpa_conf    — read /etc/wpa_supplicant/wpa_supplicant.conf,
 *                        present an N-network editor with SSID/PSK,
 *                        accept POST submission to rewrite the file.
 *
 * Style/JS helpers live under admin/wifi/ — phpincs.php (helper
 * functions like ConvertToChannel, ConvertToSecurity), styles.php
 * (CSS), functions.js (client-side validation).
 *
 * On Save: writes a fresh wpa_supplicant.conf to /tmp/wifidata, then
 * `sudo mount -o remount,rw / && sudo cp -f /tmp/wifidata
 * /etc/wpa_supplicant/wpa_supplicant.conf && ... && sudo mount -o
 * remount,ro /`. PSKs are stored both in plaintext as a `#psk=`
 * comment (so the dashboard can re-display them later) and as a
 * pbkdf2 hash via hash_pbkdf2() under the actual `psk=` key.
 *
 * NOTE for the security pass: SSID/PSK values are interpolated into
 * the wpa_supplicant.conf template without escaping — an SSID
 * containing `"` could break out of the quoted-string section.
 * Flagged for the security pass; no fix in this commit.
 */
require_once($_SERVER['DOCUMENT_ROOT'].'/config/security_headers.php');
require_once($_SERVER['DOCUMENT_ROOT'].'/config/csrf.php');
require_once($_SERVER['DOCUMENT_ROOT'].'/config/banner_warnings.inc');
setSecurityHeaders();

// CSRF protection — see config/csrf.php for the full rationale.
// Must run BEFORE any output: bootstraps the session on GET (so
// Set-Cookie ships) and rejects forged POSTs (Reset WiFi adapter,
// SaveWPAPSKSettings) cleanly with 403 before any side effect.
csrf_verify();

// Layer 2 of the default-password protection — see config/banner_warnings.inc.
// MUST run BEFORE any output so header('Location: ...') works.
pistar_warnings_enforce_redirect();

include('wifi/phpincs.php');
$output = $return = 0;
$page = $_GET['page'];


echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta name="Author" content="Andrew Taylor (MW0MWZ)" />
<meta name="Description" content="Pi-Star Configuration" />
<meta name="KeyWords" content="Pi-Star, MW0MWZ" />
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
<meta http-equiv="pragma" content="no-cache" />
<link rel="shortcut icon" href="images/favicon.ico" type="image/x-icon" />
<meta http-equiv="Expires" content="0" />
<link rel="stylesheet" type="text/css" href="css/pistar-css.php" />
<link rel="stylesheet" type="text/css" href="wifi/styles.php" />
<script type="text/Javascript" src="wifi/functions.js?version=1.6"></script>
<title>Pi-Star - Digital Voice Dashboard - WiFi Config</title>
</head>
<body>'."\n";
switch($page) {
    case "wlan0_info":
        //Declare a pile of variables
        $strIPAddress = NULL;
        $strNetMask = NULL;
        $strRxPackets = NULL;
        $strRxBytes = NULL;
        $strTxPackets = NULL;
        $strTxBytes = NULL;
        $strSSID = NULL;
        $strBSSID = NULL;
        $strBitrate = NULL;
        $strTxPower = NULL;
        $strLinkQuality = NULL;
        $strSignalLevel = NULL;
        $strWifiFreq = NULL;
        $strWifiChan = NULL;

        exec('ifconfig wlan0',$return);
        exec('iwconfig wlan0',$return);
        exec('iw dev wlan0 link',$return);
        $strWlan0 = implode(" ",$return);
        $strWlan0 = preg_replace('/\s\s+/', ' ', $strWlan0);
        if (strpos($strWlan0,'HWaddr') !== false) {
            preg_match('/HWaddr ([0-9a-f:]+)/i',$strWlan0,$result);
            $strHWAddress = $result[1];
        }
        if (strpos($strWlan0,'ether') !== false) {
            preg_match('/ether ([0-9a-f:]+)/i',$strWlan0,$result);
            $strHWAddress = $result[1];
        }
        if(strpos($strWlan0, "UP") !== false && strpos($strWlan0, "RUNNING") !== false) {
            $strStatus = '<span style="color:green">Interface is up</span>';
                //Cant get these unless we are connected :)
                if (strpos($strWlan0,'inet addr:') !== false) {
                    preg_match('/inet addr:([0-9.]+)/i',$strWlan0,$result);
                    $strIPAddress = $result[1];
                } else {
                    preg_match('/inet ([0-9.]+)/i',$strWlan0,$result);
                    $strIPAddress = $result[1];
                }
                if (strpos($strWlan0,'Mask:') !== false) {
                    preg_match('/Mask:([0-9.]+)/i',$strWlan0,$result);
                    $strNetMask = $result[1];
                } else {
                    preg_match('/netmask ([0-9.]+)/i',$strWlan0,$result);
                    $strNetMask = $result[1];
                }
                preg_match('/RX packets.(\d+)/',$strWlan0,$result);
                $strRxPackets = $result[1];
                preg_match('/TX packets.(\d+)/',$strWlan0,$result);
                $strTxPackets = $result[1];
                if (strpos($strWlan0,'RX bytes') !== false) {
                    preg_match('/RX [B|b]ytes:(\d+ \(\d+.\d+ [K|M|G]iB\))/i',$strWlan0,$result);
                    $strRxBytes = $result[1];
                } else {
                    preg_match('/RX packets \d+ bytes (\d+ \(\d+.\d+ [K|M|G]iB\))/i',$strWlan0,$result);
                    $strRxBytes = $result[1];
                }
                if (strpos($strWlan0,'TX bytes') !== false) {
                    preg_match('/TX [B|b]ytes:(\d+ \(\d+.\d+ [K|M|G]iB\))/i',$strWlan0,$result);
                    $strTxBytes = $result[1];
                } else {
                    preg_match('/TX packets \d+ bytes (\d+ \(\d+.\d+ [K|M|G]iB\))/i',$strWlan0,$result);
                    $strTxBytes = $result[1];
                }
                //preg_match('/TX Bytes:(\d+ \(\d+.\d+ [K|M|G]iB\))/i',$strWlan0,$result);
                //$strTxBytes = $result[1];
                if (preg_match('/Access Point: ([0-9a-f:]+)/i',$strWlan0,$result)) {
                $strBSSID = $result[1]; }
                if (preg_match('/Connected to\ ([0-9a-f:]+)/i',$strWlan0,$result)) {
                $strBSSID = $result[1]; }
                if (preg_match('/Bit Rate([=:0-9\.]+ Mb\/s)/i',$strWlan0,$result)) {
                $strBitrate = str_replace(':', '', str_replace('=', '', $result[1])); }
                if (preg_match('/tx bitrate:\ ([0-9\.]+ Mbit\/s)/i',$strWlan0,$result)) {
                $strBitrate = str_replace(':', '', str_replace('=', '', $result[1])); }
                if (preg_match('/Tx-Power=([0-9]+ dBm)/i',$strWlan0,$result)) {
                $strTxPower = $result[1]; }
                if (preg_match('/ESSID:\"([a-zA-Z0-9-_.\s]+)\"/i',$strWlan0,$result)) {
                $strSSID = str_replace('"','',$result[1]); }
                if (preg_match('/SSID:\ ([a-zA-Z0-9-_.\s]+)/i',$strWlan0,$result)) {
                $strSSID = str_replace(' freq','',$result[1]); }
                if (preg_match('/Link Quality=([0-9]+\/[0-9]+)/i',$strWlan0,$result)) {
                        $strLinkQuality = $result[1];
                                        if (strpos($strLinkQuality, "/")) {
                                                $arrLinkQuality = explode("/", $strLinkQuality);
                                                $strLinkQuality = number_format(($arrLinkQuality[0] / $arrLinkQuality[1]) * 100)." &#37;";
                                        }
                                }
                if (preg_match('/Signal Level=(-[0-9]+ dBm)/i',$strWlan0,$result)) {
                $strSignalLevel = $result[1]; }
                if (preg_match('/Signal Level=([0-9]+\/[0-9]+)/i',$strWlan0,$result)) {
                $strSignalLevel = $result[1]; }
                if (preg_match('/signal:\ (-[0-9]+ dBm)/i',$strWlan0,$result)) {
                $strSignalLevel = $result[1]; }
                if (preg_match('/Frequency:([0-9.]+ GHz)/i',$strWlan0,$result)) {
                                $strWifiFreq = $result[1];
                $strWifiChan = str_replace(" GHz", "", $strWifiFreq);
                                $strWifiChan = str_replace(".", "", $strWifiChan);
                $strWifiChan = ConvertToChannel(str_replace(".", "", $strWifiChan)); }
        }
        else {
            $strStatus = '<span style="color:red">Interface is down</span>';
        }
        if(isset($_POST['ifdown_wlan0'])) {
            exec('ifconfig wlan0 | grep -i running | wc -l',$test);
            if($test[0] == 1) {
                exec('sudo ifdown wlan0',$return);
            }
            else {
                echo 'Interface already down';
            }
        }
        elseif(isset($_POST['ifup_wlan0'])) {
            exec('ifconfig wlan0 | grep -i running | wc -l',$test);
            if($test[0] == 0) {
                exec('sudo ifup wlan0',$return);
            }
            else {
                echo 'Interface already up';
            }
        }
        elseif(isset($_POST['reset_wlan0'])) {
            exec('sudo wpa_cli reconfigure wlan0 && sudo ifdown wlan0 && sleep 3 && sudo ifup wlan0 && sudo wpa_cli scan',$test);
            echo '<script>window.location.href=\'wifi.php?page=wlan0_info\';</script>';
        }

    echo '<script type="text/javascript">setTimeout(function () { location.reload(1); }, 15000);</script>
<div class="infobox">
<form action="'.$_SERVER['PHP_SELF'].'?page=wlan0_info" method="post">';
    csrf_field();
    echo '
<!-- <input type="submit" value="ifdown wlan0" name="ifdown_wlan0" /> -->
<!-- <input type="submit" value="ifup wlan0" name="ifup_wlan0" /> -->
<!-- <input type="button" value="Refresh" onclick="document.location.reload(true)" /> -->
<input type="button" value="Refresh" onclick="window.location.href=\'wifi.php?page=wlan0_info\'" />
<input type="submit" value="Reset WiFi Adapter" name="reset wlan0" />
<input type="button" value="Configure WiFi" name="wpa_conf" onclick="document.location=\'?page=\'+this.name" />
</form>
<div class="infoheader">Wireless Information and Statistics</div>
<div class="intinfo"><div class="intheader">Interface Information</div>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Interface Name : wlan0<br />
&nbsp;&nbsp;&nbsp;&nbsp;Interface Status : ' . $strStatus . '<br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;IP Address : ' . $strIPAddress . '<br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Subnet Mask : ' . $strNetMask . '<br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Mac Address : ' . $strHWAddress . '<br />
<br />
<div class="intheader">Interface Statistics</div>
&nbsp;&nbsp;&nbsp;&nbsp;Received Packets : ' . $strRxPackets . '<br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Received Bytes : ' . $strRxBytes . '<br />
&nbsp;Transferred Packets : ' . $strTxPackets . '<br />
&nbsp;&nbsp;&nbsp;Transferred Bytes : ' . $strTxBytes . '<br />
<br />
</div>
<div class="wifiinfo">
<div class="intheader">Wireless Information</div>
&nbsp;&nbsp;&nbsp;Connected To : ' . $strSSID . '<br />
&nbsp;AP Mac Address : ' . $strBSSID . '<br />
<br />
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Bitrate : ' . $strBitrate . '<br />
&nbsp;&nbsp;&nbsp;Signal Level : ' . $strSignalLevel . '<br />
<br />';
if ($strTxPower) { echo '&nbsp;Transmit Power : ' . $strTxPower .'<br />'."\n"; } else { echo "<br />\n"; }
if ($strLinkQuality) { echo '&nbsp;&nbsp;&nbsp;Link Quality : ' . $strLinkQuality . '<br />'."\n"; } else { echo "<br />\n"; }
if (($strWifiFreq) && ($strWifiChan) && ($strWifiChan != "Invalid Channel")) {
    echo '&nbsp;&nbsp;&nbsp;Channel Info : ' . $strWifiChan . ' (' . $strWifiFreq . ')<br />'."\n";
} else {
    echo "<br />\n";
}
if (file_exists('/etc/wpa_supplicant/wpa_supplicant.conf')) {
        exec('sudo grep "country" /etc/wpa_supplicant/wpa_supplicant.conf', $wifiCountryArr);
        }
if (isset($wifiCountryArr[0])) {
        $wifiCountry = explode("=", $wifiCountryArr[0]);
        if (isset($wifiCountry[1])) {
                // Same hardening rationale as the SSID/PSK display in
                // the wpa_conf branch: country comes from grep'ing
                // wpa_supplicant.conf, save handler now constrains it
                // to /\A[A-Z]{2}\z/, but the file may already contain
                // pre-validation or hand-edited values.
                echo '&nbsp;&nbsp;&nbsp;WiFi Country : '.htmlspecialchars((string)$wifiCountry[1], ENT_QUOTES, 'UTF-8')."<br />\n";
                }
        }
echo '<br />
<br />
</div>
<br />
</div>
<div class="intfooter">Information provided by ifconfig and iwconfig</div>';
    break;

    case "wpa_conf":
        exec('sudo cat /etc/wpa_supplicant/wpa_supplicant.conf',$return);
        $ssid = array();
        $psk = array();
        foreach($return as $a) {
            if(preg_match('/country=/i',$a)) {
                $wifiCountryArr = explode("=",$a);
                $wifiCountry = $wifiCountryArr[1];
            }

            // Make sure we only put ONE SSID and matching PSK into the arrays
                        if ( ( isset($curssidplain) || isset($curssidalt) ) && ( isset($curpskplain) || isset($curpskalt) ) ) {
                                if (isset($curssidplain)) { $ssid[] = $curssidplain; unset($curssidplain); unset($curssidalt); }
                                if (isset($curssidalt))   { $ssid[] = $curssidalt;   unset($curssidplain); unset($curssidalt); }
                                if (isset($curpskplain))  { $psk[]  = $curpskplain;  unset($curpskplain);  unset($curpskalt);  }
                                if (isset($curpskalt))    { $psk[]  = $curpskalt;    unset($curpskplain);  unset($curpskalt);  }
                        }

                        // Handle the case of the old file format, and the new...
                        if(preg_match('/\#SSID=/i',$a) && !preg_match('/scan_ssid/i',$a)) {
                                $arrssid = explode("=",$a);
                                //$ssid[] = str_replace('"','',$arrssid[1]);
                                $curssidplain = str_replace('"','',$arrssid[1]);
                        }
                        elseif(preg_match('/SSID="/i',$a) && !preg_match('/scan_ssid/i',$a)) {
                                $arrssid = explode("=",$a);
                                //$ssid[] = str_replace('"','',$arrssid[1]);
                                if (!isset($curssidplain)) { $curssidalt = str_replace('"','',$arrssid[1]); }
                        }
                        if (isset($curssidplain) || isset($curssidalt)) {
                                if(preg_match('/\#psk="/i',$a)) {
                                        $arrpsk = explode("=",$a);
                                        //$psk[] = str_replace('"','',$arrpsk[1]);
                                        $curpskplain = str_replace('"','',$arrpsk[1]);
                                }
                                elseif(preg_match('/psk=/i',$a)) {
                                        $arrpsk = explode("=",$a);
                                        //$psk[] = str_replace('"','',$arrpsk[1]);
                                        if (!isset($curpskplain)) { $curpskalt = str_replace('"','',$arrpsk[1]); }
                                }
                        }
        }
        $numSSIDs = count($ssid);
        $output = '<form method="post" action="'.$_SERVER['PHP_SELF'].'?page=wpa_conf" id="wpa_conf_form">'
                . csrf_field_html() . '
<input type="button" value="WiFi Info" name="wlan0_info" onclick="document.location=\'?page=\'+this.name" /><br />
<input type="hidden" id="Networks" name="Networks" />
<div class="network" id="networkbox">'."\n";
        if (!isset($wifiCountry)) { $wifiCountry = "JP"; }
        $output .= 'WiFi Regulatory Domain (Country Code) : <select name="wifiCountryCode">'."\n";
        if (file_exists('/lib/crda/regulatory.bin')) {
            exec('regdbdump /lib/crda/regulatory.bin | fgrep country | cut -b 9-10', $regDomains);
        } elseif (file_exists('/lib/crda/db.txt')) {
            exec('cat /lib/crda/db.txt | fgrep country | cut -b 9-10', $regDomains);
        } else {
            $regDomains = array("AU","FR","DE","GB","US","JP");
        }
        foreach($regDomains as $regDomain) {
            if ($regDomain == $wifiCountry) {
                $output .= '<option value="'.$regDomain.'" selected>'.$regDomain.'</option>'."\n";
            } else {
                $output .= '<option value="'.$regDomain.'">'.$regDomain.'</option>'."\n";
            }
        }
        $output .= '</select><br />'."\n";

        for($ssids = 0; $ssids < $numSSIDs; $ssids++) {
            // Escape SSID/PSK before interpolating into `value="..."`.
            // Source: /etc/wpa_supplicant/wpa_supplicant.conf parsed
            // a few lines up. The save handler now strictly validates
            // SSIDs/PSKs (printable ASCII, no `"` or `\`) so anything
            // written by THIS dashboard going forward is safe — but
            // the file may already contain values written by an
            // older release or hand-edited via SSH, so display-side
            // escaping closes the stored-XSS path.
            //
            // Round-trip: htmlspecialchars(ENT_QUOTES) is reversed by
            // the browser when it decodes the value="..." attribute,
            // so the form POSTs back the original bytes and re-saves
            // unchanged for any value the save validator accepts.
            $ssidHtml = htmlspecialchars((string)$ssid[$ssids], ENT_QUOTES, 'UTF-8');
            $pskHtml  = htmlspecialchars((string)$psk[$ssids],  ENT_QUOTES, 'UTF-8');
            $output .= '<div id="Networkbox'.$ssids.'" class="NetworkBoxes">Network '.$ssids."\n";
            $output .= '<input type="button" value="Delete" onclick="DeleteNetwork('.$ssids.')" /><br />'."\n";
            $output .= '<span class="tableft" id="lssid'.$ssids.'">SSID :</span><input type="text" id="ssid'.$ssids.'" name="ssid'.$ssids.'" value="'.$ssidHtml.'" onkeyup="CheckSSID(this)" /><br />'."\n";
            $output .= '<span class="tableft" id="lpsk'.$ssids.'">PSK :</span><input type="password" id="psk'.$ssids.'" name="psk'.$ssids.'" value="'.$pskHtml.'" onkeyup="CheckPSK(this)" /><br /><br /></div>'."\n";
        }
        $output .= '</div>'."\n";
        $output .= '<div class="infobox">'."\n";
        $output .= '<input type="submit" value="Scan for Networks (10 secs)" name="Scan" />'."\n";
        $output .= '<input type="button" value="Add Network" onclick="AddNetwork();" />'."\n";
        $output .= '<input type="submit" value="Save (and connect)" name="SaveWPAPSKSettings" onmouseover="UpdateNetworks(this)" />'."\n";
        $output .= '</div>'."\n";
        $output .= '</form>'."\n";


    echo $output;
    echo '<script type="text/Javascript">UpdateNetworks()</script>';

    if(isset($_POST['SaveWPAPSKSettings'])) {
        // Strict validation BEFORE we build the config string.
        //
        // Why: the previous implementation interpolated $_POST values
        // (wifiCountryCode, ssid<N>, psk<N>) directly into the
        // wpa_supplicant.conf template. None of those values were
        // escaped for the surrounding `"..."` / `network={ ... }`
        // shell-of-config context. An SSID containing `"\n}\n` would
        // break out of the string, close the `network={` block, and
        // let the attacker append additional `network={ ... }` /
        // `ctrl_interface=...` directives — including a forced join
        // to an attacker-controlled AP at next reboot, opening up
        // DNS-rebind / MITM attacks on the rest of the LAN.
        //
        // Validation rules (per IEEE 802.11 + wpa_supplicant.conf
        // syntactic safety):
        //   - country: exactly 2 uppercase ASCII letters (ISO 3166-1)
        //   - SSID:    1-32 bytes of printable ASCII, NO `"` and NO
        //              `\` (those are the breakout chars inside the
        //              `"..."` form). Special wildcard `*` allowed.
        //   - PSK:     empty (open network) OR 8-63 printable ASCII
        //              chars excluding `"` and `\` (the WPA passphrase
        //              charset, narrowed to remove breakout chars) OR
        //              exactly 64 hex chars (raw pre-shared key).
        //
        // The bin2hex(ssid) and hash_pbkdf2(psk, ssid) outputs that
        // make it into the FINAL `ssid=` and `psk=` lines are hex
        // strings by construction, so they were never the injection
        // path. The injection path was the COMMENT lines
        // (#ssid="..." / #psk="...") and the open-network
        // `ssid="..."` line. Constraining the inputs here closes
        // every variant.
        $errors = array();

        $rawCountry = isset($_POST['wifiCountryCode']) ? (string)$_POST['wifiCountryCode'] : '';
        if (!preg_match('/\A[A-Z]{2}\z/', $rawCountry)) {
            $errors[] = 'WiFi country code must be exactly 2 uppercase letters (ISO 3166-1 alpha-2)';
        }

        $networksCount = isset($_POST['Networks']) ? (int)$_POST['Networks'] : 0;
        if ($networksCount < 0 || $networksCount > 32) {
            $errors[] = 'network count out of range';
            // Clamp so the validation loop below doesn't spin on a
            // hostile count. The non-empty $errors above will skip
            // the config-build branch anyway, so behaviour is the
            // same — this is defence in depth.
            $networksCount = 0;
        }

        // Per-network validation. SSID and PSK regexes use the
        // explicit byte ranges \x20-\x21 + \x23-\x5b + \x5d-\x7e —
        // i.e. printable ASCII minus `"` (0x22) and `\` (0x5c). Both
        // are syntactic in the wpa_supplicant.conf `"..."` form;
        // letting them through is what made the original injection
        // possible.
        $validated = array();
        for ($x = 0; $x < $networksCount; $x++) {
            $ssid = isset($_POST['ssid'.$x]) ? (string)$_POST['ssid'.$x] : '';
            $psk  = isset($_POST['psk'.$x])  ? (string)$_POST['psk'.$x]  : '';

            if ($ssid !== '*' &&
                !preg_match('/\A[\x20-\x21\x23-\x5b\x5d-\x7e]{1,32}\z/', $ssid)) {
                $errors[] = 'network ' . $x . ': SSID must be 1-32 printable ASCII characters and may not contain `"` or `\\`';
            }

            $pskOk = ($psk === '')
                  || preg_match('/\A[0-9A-Fa-f]{64}\z/', $psk)
                  || preg_match('/\A[\x20-\x21\x23-\x5b\x5d-\x7e]{8,63}\z/', $psk);
            if (!$pskOk) {
                $errors[] = 'network ' . $x . ': PSK must be 8-63 printable ASCII characters (no `"` or `\\`) or exactly 64 hex characters';
            }

            $validated[] = array('ssid' => $ssid, 'psk' => $psk);
        }

        if (!empty($errors)) {
            echo "<b>WiFi configuration NOT saved.</b><br />\n";
            foreach ($errors as $err) {
                echo "&nbsp;&nbsp;- " . htmlspecialchars($err, ENT_QUOTES, 'UTF-8') . "<br />\n";
            }
            echo "Please correct the input and try again.<br />\n";
        } else {
            $config = "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\nupdate_config=1\nap_scan=1\nfast_reauth=1\ncountry=" . $rawCountry . "\n\n";

            foreach ($validated as $x => $net) {
                $ssid = $net['ssid'];
                $psk = $net['psk'];
                $priority = 100 - $x;
                if ($ssid == "*" && !$psk) { $config .= "network={\n\t#ssid=\"$ssid\"\n\t#psk=\"\"\n\tkey_mgmt=NONE\n\tid_str=\"$x\"\n\tpriority=$priority\n\tscan_ssid=1\n}\n\n"; }
                elseif ($ssid && !$psk) { $config .= "network={\n\tssid=\"$ssid\"\n\t#psk=\"\"\n\tkey_mgmt=NONE\n\tid_str=\"$x\"\n\tpriority=$priority\n\tscan_ssid=1\n}\n\n"; }
                elseif ($ssid && $psk) {
                    $pskSalted = hash_pbkdf2("sha1", $psk, $ssid, 4096, 64);
                    $ssidHex = bin2hex("$ssid");
                    $config .= "network={\n\t#ssid=\"$ssid\"\n\tssid=$ssidHex\n\t#psk=\"$psk\"\n\tpsk=$pskSalted\n\tid_str=\"$x\"\n\tpriority=$priority\n\tscan_ssid=1\n}\n\n";
                }
            }
            file_put_contents('/tmp/wifidata', $config);
            system('sudo mount -o remount,rw / && sudo cp -f /tmp/wifidata /etc/wpa_supplicant/wpa_supplicant.conf && sudo sync && sudo sync && sudo sync && sudo mount -o remount,ro /');
            echo "Wifi Settings Updated Successfully\n";
            // If Auto AP is on, don't restart the WiFi Card.
            if (!file_exists('/sys/class/net/wlan0_ap')) {
                exec('sudo ip link set wlan0 down && sleep 3 && sudo ip link set wlan0 up');
            }
            echo "<script>document.location='?page=\wlan0_info'</script>";
        }

    } elseif(isset($_POST['Scan'])) {
        $return = '';
        exec('ifconfig wlan0 | grep -i running | wc -l',$test);
        exec('sudo wpa_cli scan -i wlan0',$return);
        sleep(8);
        exec('sudo wpa_cli scan_results -i wlan0',$return);
        unset($return['0']); // This is a better way to clean up;
        unset($return['1']); // This is a better way to clean up;
        echo "<br />\n";
        echo "Networks found : <br />\n";
        echo "<table>\n";
        echo "<tr><th>Connect</th><th>SSID</th><th>Channel</th><th>Signal</th><th>Security</th></tr>";
        foreach($return as $network) {
            $arrNetwork = preg_split("/[\t]+/",$network);
            $bssid = $arrNetwork[0];
            $channel = ConvertToChannel($arrNetwork[1]);
            $signal = $arrNetwork[2] . " dBm";
            $security = ConvertToSecurity($arrNetwork[3]);
            $ssid = $arrNetwork[4];

            // SSID is broadcast by the access point and is operator-
            // controlled at the AP — i.e. attacker-controlled if a
            // rogue AP is in RF range. Without escaping, an SSID like
            //   '); alert(1); //
            // would execute JavaScript inside the dashboard the moment
            // the operator opened the WiFi scan page (no auth bypass
            // needed; the operator's own browser runs the payload).
            // Two contexts to escape for:
            //
            //   - HTML cell content   -> htmlspecialchars
            //   - JS string literal inside onclick="…(…)" -> json_encode
            //     wraps the value in safe JS double-quotes; an outer
            //     htmlspecialchars makes it safe inside the HTML
            //     attribute (which is also double-quoted).
            //
            // The other fields ($channel, $signal, $security) come
            // from wpa_cli output rather than the AP's own broadcast,
            // so they're already constrained — but htmlspecialchars
            // them too as defence in depth.
            $ssidHtml = htmlspecialchars($ssid, ENT_QUOTES, 'UTF-8');
            $ssidJs   = htmlspecialchars(
                json_encode($ssid, JSON_HEX_TAG | JSON_HEX_AMP
                                 | JSON_HEX_APOS | JSON_HEX_QUOT),
                ENT_QUOTES, 'UTF-8'
            );
            $channelHtml  = htmlspecialchars((string)$channel, ENT_QUOTES, 'UTF-8');
            $signalHtml   = htmlspecialchars($signal,   ENT_QUOTES, 'UTF-8');
            $securityHtml = htmlspecialchars($security, ENT_QUOTES, 'UTF-8');

            echo '<tr>';
            echo '<td style="text-align: left;"><input type="button" value="Select" onclick="AddScanned('.$ssidJs.')" /></td>';
            echo '<td style="text-align: left;">'.$ssidHtml.'</td>';
            echo '<td style="text-align: left;">'.$channelHtml.'</td>';
            echo '<td>'.$signalHtml.'</td>';
            echo '<td style="text-align: left;">'.$securityHtml.'</td>';
            echo '</tr>'."\n";

        }
        echo "</table>\n";
    }

    break;
}


echo '
<div class="tail">.</div>
</body>
</html>';
