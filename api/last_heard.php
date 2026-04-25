<?php
/**
 * JSON API: recent transmissions ("last heard" feed).
 *
 * The only JSON endpoint exposed by the dashboard. Returns the in-memory
 * `$lastHeard` array — populated as a side effect of including
 * `mmdvmhost/functions.php` — as a JSON array, newest call first.
 *
 * Query string:
 *   ?num_transmissions=N   Cap the number of entries returned. When
 *                          omitted, every entry currently in memory is
 *                          returned (typically the last 30 calls).
 *
 * Response shape — array of objects with these string fields:
 *   time_utc, mode, callsign, callsign_suffix, target, src,
 *   duration, loss, bit_error_rate, rssi
 *
 * Example:
 *   GET /api/last_heard.php?num_transmissions=5
 *
 * NOTE: this endpoint does not currently call any of the
 * config/security_headers.php helpers — flagged for the security pass.
 */


require_once($_SERVER['DOCUMENT_ROOT'] . '/config/security_headers.php');
setSecurityHeaders();

include_once $_SERVER['DOCUMENT_ROOT'] . '/config/config.php';        // Dashboard runtime constants
include_once $_SERVER['DOCUMENT_ROOT'] . '/mmdvmhost/tools.php';      // Helpers (format_time, isProcessRunning, ...)
include_once $_SERVER['DOCUMENT_ROOT'] . '/mmdvmhost/functions.php';  // Populates $lastHeard

header('Content-type: application/json');

$json_response = array();

$trans_history_count = count($lastHeard);

// Cap to caller's requested count, but never exceed what's in memory.
// `intval()` defends against non-numeric query strings (returns 0).
$num_transmissions = isset($_GET['num_transmissions'])
    ? intval($_GET['num_transmissions'])
    : $trans_history_count;
$transmissions = array_slice($lastHeard, 0, min($num_transmissions, $trans_history_count));

// $lastHeard is a positional array (one row per call) where each row is
// itself a positional array. The index → field name mapping below is the
// stable contract for this endpoint; do not reorder without bumping a
// version, callers depend on these names.
foreach ($transmissions as $transmission) {
    $transmission_json = array();
    $transmission_json['time_utc']        = trim($transmission[0]);
    $transmission_json['mode']            = trim($transmission[1]);
    $transmission_json['callsign']        = trim($transmission[2]);
    $transmission_json['callsign_suffix'] = trim($transmission[3]);
    $transmission_json['target']          = trim($transmission[4]);
    $transmission_json['src']             = trim($transmission[5]);
    $transmission_json['duration']        = trim($transmission[6]);
    $transmission_json['loss']            = trim($transmission[7]);
    $transmission_json['bit_error_rate']  = trim($transmission[8]);
    $transmission_json['rssi']            = trim($transmission[9]);

    $json_response[] = $transmission_json;
}
echo json_encode($json_response);
