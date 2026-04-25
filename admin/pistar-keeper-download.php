<?php
/**
 * PiStar-Keeper logbook download.
 *
 * Sends /var/pistar-keeper/pistar-keeper.log as a binary download.
 * Linked from /admin/admin.php's PiStar-Keeper Logbook panel
 * (which only renders if pistar-keeper is running).
 *
 * NOTE for the security pass: no setSecurityHeaders() call, no auth
 * check, no PHP_SELF guard. Coverage gap.
 */

$file = '/var/pistar-keeper/pistar-keeper.log';

if (file_exists($file)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file). '"');
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    flush();
    readfile($file);
    exit;
}
