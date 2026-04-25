<?php
/**
 * Local paths and identity for ircDDBGateway-related dashboard code.
 *
 * Defines where the gateway's logs and config files live on the device,
 * plus the local callsign placeholder. The dashboard reads these paths
 * to render the D-Star and CCS panels and to back the configure.php
 * editor. `configure.php` rewrites `$callsign=` here when the operator
 * changes their callsign.
 */

// Log directory and the four ircDDBGateway-managed log files.
$logPath      = '/var/log/pi-star';
$starLogPath  = $logPath . '/STARnet.log';
$linkLogPath  = $logPath . '/Links.log';
$hdrLogPath   = $logPath . '/Headers.log';
$ddmode_log   = $logPath . '/DDMode.log';

// Local node identity (rewritten by configure.php).
$callsign    = 'M1ABC';
$registerURL = '';

// On-disk locations the dashboard reads/writes.
$configPath        = '/etc';
$gatewayConfigPath = '/etc/ircddbgateway';
$defaultConfPath   = '/etc/default';
$sharedFilesPath   = '/usr/local/etc';
$sysConfigPath     = '/etc/sysconfig';
