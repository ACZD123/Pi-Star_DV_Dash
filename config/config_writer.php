<?php
/**
 * Pi-Star configuration writer — safe replacement for the long-standing
 * `sudo sed -i "/key=/c\\key=$value"` pattern that's repeated ~150 times
 * across admin/configure.php.
 *
 * The previous approach concatenated `escapeshellcmd($_POST['field'])`
 * into a double-quoted shell command and a sed `c\` replacement.
 * `escapeshellcmd()` does not protect double-quoted shell contexts, so
 * each call site was an independent command-injection sink. This helper
 * replaces the family of sites with a single staged-write API: edits
 * accumulate in memory, commit() writes them all at once via PHP-side
 * file editing plus an atomic `sudo install`, and no shell ever sees
 * an attacker-controlled byte.
 *
 * Usage from a POST handler:
 *
 *     require_once $_SERVER['DOCUMENT_ROOT'] . '/config/config_writer.php';
 *
 *     // Stage individual edits — accumulate in memory, no I/O yet.
 *     config_writer_stage_flat('/etc/ircddbgateway', 'aprsHostname',  $aprsHost);
 *     config_writer_stage_flat('/etc/ircddbgateway', 'remotePassword', $confPass);
 *     config_writer_stage_flat('/etc/timeserver',    'callsign',       $newCall);
 *     // ... many more ...
 *
 *     // Commit all staged edits — one remount-rw / batched-install / remount-ro cycle.
 *     $errors = config_writer_commit();
 *     if (!empty($errors)) {
 *         // Each entry is a human-readable diagnostic; surface or log as you prefer.
 *     }
 *
 * Design choices:
 *
 *   - **Allowlist of writable paths.** Any caller asking to write outside
 *     the allowlist gets `false` back from `config_writer_stage_flat()`
 *     (and an `error_log()` entry). The list is the set of flat
 *     key=value files the dashboard's editor surfaces actually edit.
 *
 *   - **Stage-then-commit, single mount cycle.** The dashboard runs on
 *     a read-only rootfs by default. A naive per-edit `remount,rw` /
 *     write / `remount,ro` cycle would race when many edits land in one
 *     POST (and configure.php has 150+ such edits per save). Staging
 *     all edits in `$GLOBALS['__config_writer_stage']` and flushing in a
 *     single `commit()` call collapses that to one mount cycle per POST.
 *
 *   - **Match sed's `c\` semantics.** Replace the FIRST line whose head
 *     is `<key>=` (column 0 — stricter than sed's "anywhere on line"
 *     pattern, which is actually the correct intent and avoids the
 *     classic substring-collision class of bug). If the key is absent,
 *     do nothing — same as sed. Append-if-missing would be a behaviour
 *     change for daemons with strict parsers and isn't safe without a
 *     per-file audit; defer to a later opt-in flag if needed.
 *
 *   - **Atomic file replacement via `sudo install -m 644 -o root -g root`.**
 *     `cp` is not atomic — open + write + close on the destination
 *     leaves a window where the file is partially written. `install`
 *     uses rename(2) when src and dst share a filesystem; falls back to
 *     copy+chmod+chown when they don't (which is our case here — `/tmp`
 *     is tmpfs, the destination is on the SD card). The fallback is no
 *     less atomic than the existing `cp` pattern used elsewhere in this
 *     dashboard, and it sets mode/owner in one go. A future hardening
 *     pass could co-locate the staging file with the destination for
 *     true rename(2) atomicity.
 *
 *   - **Hardcoded shell command literals.** `system()` is called with a
 *     fixed-shape command string; only fixed paths and `escapeshellarg()`-
 *     wrapped arguments are interpolated. PHP's `proc_open()` array form
 *     is PHP 7.4+ and this codebase targets PHP 7.0+, so we stay with
 *     `system()` plus `escapeshellarg()` instead.
 *
 *   - **Whitespace preservation.** Existing files use `key=value` with
 *     no spaces around `=`. The helper preserves that exactly — it does
 *     NOT normalise existing files' formatting. Daemons in this stack
 *     parse their own configs with byte-precise matching; introducing
 *     spurious whitespace changes would risk breakage out of scope for
 *     this fix.
 *
 *   - **Concurrent-edits.** Pi-Star is a single-operator embedded device
 *     in practice. The read-mutate-write window in commit() is wider
 *     than sed's, but two simultaneous configure.php POSTs are vanishingly
 *     rare on the target hardware. TODO: add file locking via flock()
 *     if this assumption ever stops holding.
 */

/**
 * Allow-list of paths the helper is permitted to write. Any other path
 * passed to `config_writer_stage_flat()` is rejected with an
 * error_log() entry and a `false` return.
 *
 * Defined as a function (not a constant) so the file is safe to
 * `require_once` multiple times under PHP 7.0 — array constants from
 * `define()` work in 7.0 but `const` arrays at the file scope are
 * 5.6+ and uniform-array-syntax limits make redefinition awkward.
 *
 * @return array<int,string>
 */
function config_writer_allowed_paths()
{
    return array(
        '/etc/ircddbgateway',
        '/etc/dstarrepeater',
        '/etc/timeserver',
        '/etc/aprsgateway',
        '/etc/mobilegps',
        '/etc/hostapd/hostapd.conf',
        '/root/.Remote Control',                            // note: literal space in filename
        '/var/www/dashboard/config/ircddblocal.php',
        '/var/www/dashboard/config/language.php',
        '/var/www/dashboard/config/config.php',
    );
}

/**
 * Stage a single `key=value` edit against a flat config file.
 *
 * The edit is queued in process-local memory. Nothing touches disk
 * until {@see config_writer_commit()} runs. Multiple stages against the
 * same file accumulate; multiple stages of the same key in the same
 * file overwrite each other (last write wins) and only the last is
 * applied at commit time.
 *
 * @param string $path  Absolute path. Must appear in
 *                      {@see config_writer_allowed_paths()}.
 * @param string $key   The key name, e.g. `aprsHostname`. Must match
 *                      `[A-Za-z_][A-Za-z0-9_]*` — defence in depth so
 *                      a programming-error caller can't inject a
 *                      regex/sed metachar via the key.
 * @param string $value The new value. Must not contain NUL / CR / LF
 *                      (those would break the line-oriented file
 *                      format). All other bytes — including shell
 *                      metachars like `"` `'` `;` `&` `$` — are stored
 *                      verbatim, which is correct: the value is data,
 *                      not a shell argument.
 *
 * @return bool True if staged. False if rejected (path not allow-
 *              listed, key malformed, or value contains NUL/CR/LF).
 *              On false, an error_log() entry is emitted.
 */
function config_writer_stage_flat($path, $key, $value)
{
    if (!in_array($path, config_writer_allowed_paths(), true)) {
        error_log("config_writer: refusing to stage edit against non-allowlisted path '$path'");
        return false;
    }
    if (!preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/', $key)) {
        error_log("config_writer: refusing to stage malformed key '$key' for $path");
        return false;
    }
    if (preg_match('/[\x00\r\n]/', $value)) {
        error_log("config_writer: refusing to stage value with NUL/CR/LF for $path:$key");
        return false;
    }

    if (!isset($GLOBALS['__config_writer_stage'])) {
        $GLOBALS['__config_writer_stage'] = array();
    }
    if (!isset($GLOBALS['__config_writer_stage'][$path])) {
        $GLOBALS['__config_writer_stage'][$path] = array();
    }
    // Last write wins for repeated stages of the same key.
    $GLOBALS['__config_writer_stage'][$path][$key] = $value;
    return true;
}

/**
 * Apply every staged edit and clear the staging buffer.
 *
 * For each affected file:
 *   1. Read the file into a line array.
 *   2. For each staged `key => value`, find the FIRST line whose head
 *      is `key=` (column 0) and replace it with `key=value`. If the
 *      key is absent, the edit is silently skipped (matches sed's
 *      `c\` semantics).
 *   3. Write the rebuilt content to a tempnam() in /tmp.
 *   4. Atomically copy back via `sudo install -m 644 -o root -g root`.
 *
 * Wraps the per-file install calls in a single mount-rw / mount-ro
 * pair so concurrent POSTs can't race on remount toggles. The mount
 * calls are no-ops when the rootfs is already in the requested state
 * (Pi-Star sometimes has `/` rw between user actions).
 *
 * @return array<int,string> Diagnostic strings — empty on full success.
 *                           Non-empty entries describe per-file failures
 *                           (read failure, file_put_contents failure,
 *                           install non-zero exit). The caller decides
 *                           whether to surface to the UI or just log.
 */
function config_writer_commit()
{
    $errors = array();
    if (empty($GLOBALS['__config_writer_stage'])) {
        return $errors;
    }
    $stage = $GLOBALS['__config_writer_stage'];

    // Single mount-rw / batched-install / mount-ro envelope. If the
    // caller already opened a write window we'll just remount-rw on
    // an already-rw fs (a no-op) and remount-ro at the end, which is
    // generally what the caller wanted anyway.
    system('sudo mount -o remount,rw /');

    foreach ($stage as $path => $kvPairs) {
        if (!is_readable($path)) {
            $errors[] = "config_writer: cannot read $path; edits skipped";
            error_log("config_writer: cannot read $path; " . count($kvPairs) . " edits skipped");
            continue;
        }
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            $errors[] = "config_writer: file() failed for $path; edits skipped";
            error_log("config_writer: file() failed for $path; " . count($kvPairs) . " edits skipped");
            continue;
        }

        foreach ($kvPairs as $key => $value) {
            $prefix = $key . '=';
            $applied = false;
            foreach ($lines as $i => $line) {
                if (strpos($line, $prefix) === 0) {
                    $lines[$i] = $prefix . $value;
                    $applied = true;
                    break;
                }
            }
            // Silent no-op when the key isn't present — matches the
            // previous sed `c\` semantics. If the caller cares, log
            // here. (Quiet by default to avoid filling the log on
            // version-skew between the dashboard and the gateway
            // configs.)
            if (!$applied) {
                error_log("config_writer: $path has no '$key=' line; edit skipped");
            }
        }

        $tmp = tempnam('/tmp', 'pistar_cw_');
        if ($tmp === false) {
            $errors[] = "config_writer: tempnam() failed; $path edits skipped";
            error_log("config_writer: tempnam() failed for $path");
            continue;
        }
        $bytes = file_put_contents($tmp, implode("\n", $lines) . "\n");
        if ($bytes === false) {
            $errors[] = "config_writer: write to $tmp failed; $path edits skipped";
            error_log("config_writer: file_put_contents() failed for $tmp; $path edits skipped");
            @unlink($tmp);
            continue;
        }

        // Atomic install. Mode/owner forced to 644 root:root — matches
        // the convention every other editor in this codebase already
        // uses for these files.
        $cmd = 'sudo install -m 644 -o root -g root '
             . escapeshellarg($tmp) . ' '
             . escapeshellarg($path);
        $rc = 0;
        $out = array();
        exec($cmd . ' 2>&1', $out, $rc);
        if ($rc !== 0) {
            $errors[] = "config_writer: install exit=$rc for $path: " . implode(' / ', $out);
            error_log("config_writer: install exit=$rc for $path: " . implode(' / ', $out));
        }
        @unlink($tmp);
    }

    system('sudo mount -o remount,ro /');

    // Clear the stage so a subsequent commit() call doesn't re-apply
    // already-applied edits.
    $GLOBALS['__config_writer_stage'] = array();

    return $errors;
}
