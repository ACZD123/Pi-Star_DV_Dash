<?php
/**
 * Pi-Star Dashboard runtime constants.
 *
 * Auto-generated — be careful editing by hand; configure.php may
 * regenerate parts of this file when the operator changes settings.
 *
 * Defines paths to MMDVMHost / YSF / P25 gateway logs and config files.
 * Consumed primarily by mmdvmhost/functions.php for the data-extraction
 * layer (last-heard parsing, link state lookup, mode detection).
 *
 * The trailing `REBOOT*` / `HALTSYS` / `TEMPERATUREHIGHLEVEL` defines
 * are placeholders kept blank by default; some legacy paths inspect
 * them via `defined()`/`!empty()`.
 */

// All log timestamps in this dashboard are interpreted as UTC.
date_default_timezone_set('UTC');

// MMDVMHost — modem driver: log path, log filename prefix, and the
// /etc filename it reads its config from.
define('MMDVMLOGPATH',      '/var/log/pi-star');
define('MMDVMLOGPREFIX',    'MMDVM');
define('MMDVMINIPATH',      '/etc');
define('MMDVMINIFILENAME',  'mmdvmhost');
define('MMDVMHOSTPATH',     '/usr/local/bin');
define('DMRIDDATPATH',      '/usr/local/etc');

// YSFGateway (Yaesu System Fusion bridge) — same shape as MMDVM.
define('YSFGATEWAYLOGPATH',     '/var/log/pi-star');
define('YSFGATEWAYLOGPREFIX',   'YSFGateway');
define('YSFGATEWAYINIPATH',     '/etc');
define('YSFGATEWAYINIFILENAME', 'ysfgateway');

// P25Gateway — same shape.
define('P25GATEWAYLOGPATH',     '/var/log/pi-star');
define('P25GATEWAYLOGPREFIX',   'P25Gateway');
define('P25GATEWAYINIPATH',     '/etc');
define('P25GATEWAYINIFILENAME', 'p25gateway');

// ircDDBGateway — D-Star side: shared `Links.log` lives here.
define('LINKLOGPATH',  '/var/log/pi-star');
define('IRCDDBGATEWAY', 'ircddbgatewayd');

// Auto-refresh hint (seconds) used by some legacy partials.
define('REFRESHAFTER', '30');

// Reserved for future use / legacy hooks. Left blank intentionally.
define('TEMPERATUREHIGHLEVEL', '');
define('REBOOTMMDVM',          '');
define('REBOOTSYS',            '');
define('HALTSYS',              '');
