<?php
/**
 * BrandMeister active-connections panel.
 *
 * AJAX-loaded partial; refreshed every 180 seconds by /index.php (slow
 * cadence on purpose — hits the BrandMeister HTTPS API). Renders a
 * read-only table of static and dynamic talkgroup subscriptions for the
 * configured DMR ID.
 *
 * Inputs:
 *   - /etc/dmrgateway              DMR network configuration; figures
 *                                  out which slot is on BrandMeister and
 *                                  the DMR ID.
 *   - /etc/bmapi.key               BrandMeister API token. Length sniff
 *                                  picks endpoint version: short → v1.0,
 *                                  long → v2 with Bearer auth.
 *   - /usr/local/etc/DMR_Hosts.txt Master name lookup for display.
 *   - https://api.brandmeister.network   Live API for TG state.
 *
 * Display-only. The companion bm_manager.php provides the link/unlink
 * form.
 *
 * NOTE for the security pass: no setEmbeddableSecurityHeaders() call.
 */


require_once($_SERVER['DOCUMENT_ROOT'] . '/config/security_headers.php');
setSecurityHeaders();

include_once $_SERVER['DOCUMENT_ROOT'].'/config/config.php';          // MMDVMDash Config
include_once $_SERVER['DOCUMENT_ROOT'].'/mmdvmhost/tools.php';        // MMDVMDash Tools
include_once $_SERVER['DOCUMENT_ROOT'].'/mmdvmhost/functions.php';    // MMDVMDash Functions
include_once $_SERVER['DOCUMENT_ROOT'].'/config/language.php';        // Translation Code

// Check if DMR is Enabled
$testMMDVModeDMR = getConfigItem("DMR", "Enable", $mmdvmconfigs);

if ( $testMMDVModeDMR == 1 ) {
  //setup BM API Key
  $bmAPIkeyFile = '/etc/bmapi.key';
  if (file_exists($bmAPIkeyFile) && fopen($bmAPIkeyFile,'r')) { $configBMapi = parse_ini_file($bmAPIkeyFile, true);
    $bmAPIkey = $configBMapi['key']['apikey'];
    // Check the BM API Key
    if ( strlen($bmAPIkey) <= 20 ) { unset($bmAPIkey); }
    if ( strlen($bmAPIkey) >= 200 ) { $bmAPIkeyV2 = $bmAPIkey; unset($bmAPIkey); }
  }

  //Load the dmrgateway config file
  $dmrGatewayConfigFile = '/etc/dmrgateway';
  if (fopen($dmrGatewayConfigFile,'r')) { $configdmrgateway = parse_ini_file($dmrGatewayConfigFile, true); }

  // Get the current DMR Master from the config
  $dmrMasterHost = getConfigItem("DMR Network", "Address", $mmdvmconfigs);
  if ( $dmrMasterHost == '127.0.0.1' ) {
    $dmrMasterHost = $configdmrgateway['DMR Network 1']['Address'];
    if (isset($configdmrgateway['DMR Network 1']['Id'])) { $dmrID = $configdmrgateway['DMR Network 1']['Id']; }
  } elseif (getConfigItem("DMR", "Id", $mmdvmconfigs)) {
    $dmrID = getConfigItem("DMR", "Id", $mmdvmconfigs);
  } else {
    $dmrID = getConfigItem("General", "Id", $mmdvmconfigs);
  }

  // Store the DMR Master IP, we will need this for the JSON lookup
  $dmrMasterHostIP = $dmrMasterHost;

  // Make sure the master is a BrandMeister Master
  $dmrMasterFile = fopen("/usr/local/etc/DMR_Hosts.txt", "r");
  while (!feof($dmrMasterFile)) {
                $dmrMasterLine = fgets($dmrMasterFile);
                $dmrMasterHostF = preg_split('/\s+/', $dmrMasterLine);
                if ((strpos($dmrMasterHostF[0], '#') === FALSE) && ($dmrMasterHostF[0] != '')) {
                        if ($dmrMasterHost == $dmrMasterHostF[2]) { $dmrMasterHost = str_replace('_', ' ', $dmrMasterHostF[0]); }
                }
  }

  if (substr($dmrMasterHost, 0, 2) == "BM") {

  // Use BM API to get information about current TGs
  $jsonContext = stream_context_create(array('http'=>array('timeout' => 2, 'header' => 'User-Agent: Pi-Star Dashboard for '.$dmrID) )); // Add Timout and User Agent to include DMRID
  if (isset($bmAPIkeyV2)) {
    $json = json_decode(@file_get_contents("https://api.brandmeister.network/v2/device/$dmrID/profile", true, $jsonContext));
  } else {
    $json = json_decode(@file_get_contents("https://api.brandmeister.network/v1.0/repeater/?action=PROFILE&q=$dmrID", true, $jsonContext));
  }

  // Set some Variable
  $bmStaticTGList = "";
  $bmDynamicTGList = "";

  // Pull the information from JSON. talkgroup/slot are documented
  // as integers in the BrandMeister API but PHP's json_decode
  // doesn't enforce that — cast to (int) so a hostile / compromised
  // upstream response can't smuggle HTML/JS into the rendered <td>
  // bytes below. (int) of a non-numeric string is 0, which renders
  // as plain "0" — predictable, inert.
  if (isset($json->staticSubscriptions)) { $bmStaticTGListJson = $json->staticSubscriptions;
                                          foreach($bmStaticTGListJson as $staticTG) {
                                            $tgNum = (int)$staticTG->talkgroup;
                                            $tgSlot = (int)$staticTG->slot;
                                            if (getConfigItem("DMR Network", "Slot1", $mmdvmconfigs) && $tgSlot === 1) {
                                              $bmStaticTGList .= "TG".$tgNum."(".$tgSlot.") ";
                                            }
                                            else if (getConfigItem("DMR Network", "Slot2", $mmdvmconfigs) && $tgSlot === 2) {
                                              $bmStaticTGList .= "TG".$tgNum."(".$tgSlot.") ";
                                            }
                                            else if (getConfigItem("DMR Network", "Slot1", $mmdvmconfigs) == "0" && getConfigItem("DMR Network", "Slot2", $mmdvmconfigs) && $tgSlot === 0) {
                                              $bmStaticTGList .= "TG".$tgNum." ";
                                            }
                                          }
                                          $bmStaticTGList = wordwrap($bmStaticTGList, 15, "<br />\n");
                                          if (preg_match('/TG/', $bmStaticTGList) == false) { $bmStaticTGList = "None"; }
                                         } else { $bmStaticTGList = "None"; }
  if (isset($json->dynamicSubscriptions)) { $bmDynamicTGListJson = $json->dynamicSubscriptions;
                                           foreach($bmDynamicTGListJson as $dynamicTG) {
                                             $tgNum = (int)$dynamicTG->talkgroup;
                                             $tgSlot = (int)$dynamicTG->slot;
                                             if (getConfigItem("DMR Network", "Slot1", $mmdvmconfigs) && $tgSlot === 1) {
                                               $bmDynamicTGList .= "TG".$tgNum."(".$tgSlot.") ";
                                             }
                                             else if (getConfigItem("DMR Network", "Slot2", $mmdvmconfigs) && $tgSlot === 2) {
                                               $bmDynamicTGList .= "TG".$tgNum."(".$tgSlot.") ";
                                             }
                                             else if (getConfigItem("DMR Network", "Slot1", $mmdvmconfigs) == "0" && getConfigItem("DMR Network", "Slot2", $mmdvmconfigs) && $tgSlot === 0) {
                                               $bmDynamicTGList .= "TG".$tgNum." ";
                                             }
                                           }
                                           $bmDynamicTGList = wordwrap($bmDynamicTGList, 15, "<br />\n");
                                           if (preg_match('/TG/', $bmDynamicTGList) == false) { $bmDynamicTGList = "None"; }
                                          } else { $bmDynamicTGList = "None"; }

  echo '<b>Active BrandMeister Connections</b>
  <table>
    <tr>
      <th><a class=tooltip href="#">'.$lang['bm_master'].'<span><b>Connected Master</b></span></a></th>
      <th><a class=tooltip href="#">Repeater ID<span><b>The ID for this Repeater/Hotspot</b></span></a></th>
      <th><a class=tooltip href="#">Static TGs<span><b>Statically linked talkgroups</b></span></a></th>
      <th><a class=tooltip href="#">Dynamic TGs<span><b>Dynamically linked talkgroups</b></span></a></th>
    </tr>'."\n";

  echo '    <tr>'."\n";
  // $dmrMasterHost / $dmrID come from /etc/dmrgateway — operator
  // edits via the expert editor. htmlspecialchars defence-in-depth.
  // $bmStatic/DynamicTGList already contain wordwrap-injected `<br />`
  // tags by design, so they intentionally aren't escaped here; the
  // talkgroup/slot integers inside them were cast to (int) above.
  echo '      <td>'.htmlspecialchars((string)$dmrMasterHost, ENT_QUOTES, 'UTF-8').'</td>';
  echo '<td>'.htmlspecialchars((string)$dmrID, ENT_QUOTES, 'UTF-8').'</td>';
  echo '<td>'.$bmStaticTGList.'</td>';
  echo '<td>'.$bmDynamicTGList.'</td>';
  echo '</tr>'."\n";
  echo '  </table>'."\n";
  echo '  <br />'."\n";
  }
}
