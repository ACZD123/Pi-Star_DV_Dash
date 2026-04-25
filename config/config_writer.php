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
 * Allow-list of paths the helper is permitted to write via the
 * flat key=value editor. Any other path passed to
 * `config_writer_stage_flat()` is rejected with an error_log()
 * entry and a `false` return.
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
        '/etc/starnetserver',
        '/etc/hostapd/hostapd.conf',
    );
}

/**
 * Allow-list of paths the helper is permitted to write via the
 * privileged-flat editor (`config_writer_stage_privileged_flat()`).
 *
 * Same column-0 `key=value` semantics as the unprivileged flat
 * editor, but the read step uses `sudo cat` so the helper can
 * service files that are mode-600 root:root and therefore not
 * readable by www-data. The destination is restored at mode 600
 * root:root via `sudo install`. Kept separate from the flat
 * allowlist because the read path and the install mode differ.
 *
 * @return array<int,string>
 */
function config_writer_allowed_paths_privileged_flat()
{
    return array(
        '/root/.Remote Control',                            // note: literal space in filename
    );
}

/**
 * Allow-list of paths the helper is permitted to write via the
 * PHP-statement editor (`config_writer_stage_php_string()`).
 *
 * These files are PHP source files included by the dashboard at
 * runtime. Each contains one or more lines of the form
 * `$varName='value';` at column 0. The PHP-statement editor
 * rewrites the value with proper PHP-string escaping so the
 * attacker-controlled bytes can never escape the single-quoted
 * string literal — preventing PHP RCE via these files.
 *
 * Kept separate from the flat allow-list because the file shape
 * and the editing semantics are different. A path that's writable
 * under one editor is NOT automatically writable under the other.
 *
 * @return array<int,string>
 */
function config_writer_allowed_paths_php_string()
{
    return array(
        '/var/www/dashboard/config/language.php',
        '/var/www/dashboard/config/ircddblocal.php',
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
 * Stage a single PHP single-quoted string assignment edit.
 *
 * Targets PHP source files in
 * {@see config_writer_allowed_paths_php_string()} that contain a
 * line of the form `$varName='value';` at column 0. The first
 * matching line is rewritten with the new value, properly escaped
 * for a PHP single-quoted string literal — `\\` and `'` inside
 * the value are escaped to `\\\\` and `\\'` respectively. All
 * other bytes (including shell metachars `"` `;` `&` `$`) are
 * stored verbatim — they are data inside a string literal, not
 * code. This closes the PHP RCE class introduced by the previous
 * `sudo sed -i` pattern, where attacker bytes could close the
 * sed-emitted single-quote and inject arbitrary PHP statements.
 *
 * Like {@see config_writer_stage_flat()}, the edit is queued in
 * memory until {@see config_writer_commit()} runs.
 *
 * @param string $path     Absolute path. Must appear in
 *                         {@see config_writer_allowed_paths_php_string()}.
 * @param string $varName  PHP variable name (no leading `$`).
 *                         Must match `[A-Za-z_][A-Za-z0-9_]*`.
 * @param string $value    The new value to assign. Must not contain
 *                         NUL/CR/LF (those would either break PHP
 *                         parsing or break the line-oriented edit).
 *
 * @return bool True if staged. False if rejected.
 */
function config_writer_stage_php_string($path, $varName, $value)
{
    if (!in_array($path, config_writer_allowed_paths_php_string(), true)) {
        error_log("config_writer: refusing PHP-string stage for non-allowlisted path '$path'");
        return false;
    }
    if (!preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/', $varName)) {
        error_log("config_writer: refusing malformed PHP var name '$varName' for $path");
        return false;
    }
    if (preg_match('/[\x00\r\n]/', $value)) {
        error_log("config_writer: refusing PHP-string value with NUL/CR/LF for $path:\$$varName");
        return false;
    }

    if (!isset($GLOBALS['__config_writer_stage_phpstr'])) {
        $GLOBALS['__config_writer_stage_phpstr'] = array();
    }
    if (!isset($GLOBALS['__config_writer_stage_phpstr'][$path])) {
        $GLOBALS['__config_writer_stage_phpstr'][$path] = array();
    }
    $GLOBALS['__config_writer_stage_phpstr'][$path][$varName] = $value;
    return true;
}

/**
 * Stage a single `key=value` edit against a flat config file that
 * lives under root-only permissions.
 *
 * Identical contract to {@see config_writer_stage_flat()} except the
 * file is read via `sudo cat` instead of the PHP-side `file()` —
 * because mode-600 root:root paths are not readable by www-data —
 * and the destination is reinstalled at mode 600 root:root rather
 * than 644.
 *
 * The only currently-allowlisted path is `/root/.Remote Control`,
 * which holds the ircDDBGateway remote-control password and port.
 *
 * @param string $path  Absolute path. Must appear in
 *                      {@see config_writer_allowed_paths_privileged_flat()}.
 * @param string $key   Same key contract as the unprivileged flat
 *                      editor.
 * @param string $value Same value contract.
 *
 * @return bool True if staged. False if rejected.
 */
function config_writer_stage_privileged_flat($path, $key, $value)
{
    if (!in_array($path, config_writer_allowed_paths_privileged_flat(), true)) {
        error_log("config_writer: refusing privileged-flat stage for non-allowlisted path '$path'");
        return false;
    }
    if (!preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/', $key)) {
        error_log("config_writer: refusing malformed privileged-flat key '$key' for $path");
        return false;
    }
    if (preg_match('/[\x00\r\n]/', $value)) {
        error_log("config_writer: refusing privileged-flat value with NUL/CR/LF for $path:$key");
        return false;
    }

    if (!isset($GLOBALS['__config_writer_stage_priv'])) {
        $GLOBALS['__config_writer_stage_priv'] = array();
    }
    if (!isset($GLOBALS['__config_writer_stage_priv'][$path])) {
        $GLOBALS['__config_writer_stage_priv'][$path] = array();
    }
    $GLOBALS['__config_writer_stage_priv'][$path][$key] = $value;
    return true;
}

/**
 * Atomically install $newContent at $path with the given mode root:root.
 *
 * Internal helper shared by the flat and php-string commit paths.
 * Returns null on success or a single-line diagnostic on failure.
 * On failure the destination is left untouched and the temp file
 * is unlinked.
 *
 * @param string $path        Absolute destination path.
 * @param string $newContent  Full file content to install.
 *
 * @return string|null Error string, or null on success.
 */
function _config_writer_install_atomic($path, $newContent, $mode = '644')
{
    // Defence in depth — $mode is never attacker-controlled (the
    // helper's commit() picks one of two hardcoded values), but we
    // refuse anything outside the small expected set so a future
    // typo can't inadvertently widen file permissions.
    if ($mode !== '644' && $mode !== '600') {
        return "config_writer: refusing invalid mode '$mode' for $path";
    }
    $tmp = tempnam('/tmp', 'pistar_cw_');
    if ($tmp === false) {
        return "config_writer: tempnam() failed for $path";
    }
    // tempnam() creates the file mode 0600 on POSIX, but a non-default
    // umask could in theory widen it. Force-narrow before writing —
    // the temp content may be a freshly-set password.
    @chmod($tmp, 0600);
    if (file_put_contents($tmp, $newContent) === false) {
        @unlink($tmp);
        return "config_writer: file_put_contents() failed for $tmp; $path edits skipped";
    }
    $cmd = 'sudo install -m ' . $mode . ' -o root -g root '
         . escapeshellarg($tmp) . ' '
         . escapeshellarg($path);
    $rc = 0;
    $out = array();
    exec($cmd . ' 2>&1', $out, $rc);
    @unlink($tmp);
    if ($rc !== 0) {
        return "config_writer: install exit=$rc for $path: " . implode(' / ', $out);
    }
    return null;
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
 * pair so concurrent POSTs can't race on remount toggles. Callers
 * that already manage their own mount cycle (e.g. configure.php's
 * top-level POST handler, which keeps `/` rw across many edits)
 * should pass `$manageMount = false` to skip the helper's own
 * mount-rw/ro — otherwise the helper's mount-ro will prematurely
 * close the caller's write window.
 *
 * @param bool $manageMount Whether commit() should issue its own
 *                          `sudo mount -o remount,rw /` and
 *                          `... remount,ro /` around the batch.
 *                          Default true — safe for one-off callers.
 *                          Pass false from inside an already-managed
 *                          mount window.
 *
 * @return array<int,string> Diagnostic strings — empty on full success.
 *                           Non-empty entries describe per-file failures
 *                           (read failure, file_put_contents failure,
 *                           install non-zero exit). The caller decides
 *                           whether to surface to the UI or just log.
 */
function config_writer_commit($manageMount = true)
{
    $errors = array();
    $flatStage = isset($GLOBALS['__config_writer_stage'])
        ? $GLOBALS['__config_writer_stage']
        : array();
    $phpStrStage = isset($GLOBALS['__config_writer_stage_phpstr'])
        ? $GLOBALS['__config_writer_stage_phpstr']
        : array();
    $privStage = isset($GLOBALS['__config_writer_stage_priv'])
        ? $GLOBALS['__config_writer_stage_priv']
        : array();

    if (empty($flatStage) && empty($phpStrStage) && empty($privStage)) {
        return $errors;
    }

    // Optional single mount-rw / batched-install / mount-ro envelope.
    // When the caller already has `/` open rw (configure.php's POST
    // handler does this for the duration of a save), we MUST NOT do
    // our own mount-ro at the end — that would prematurely close the
    // caller's window and break later writes (e.g. the timezone
    // handler that runs after this commit).
    if ($manageMount) {
        system('sudo mount -o remount,rw /');
    }

    // Pass 1 — flat key=value edits.
    foreach ($flatStage as $path => $kvPairs) {
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

        $err = _config_writer_install_atomic(
            $path,
            implode("\n", $lines) . "\n"
        );
        if ($err !== null) {
            $errors[] = $err;
            error_log($err);
        }
    }

    // Pass 2 — PHP single-quoted string assignment edits.
    foreach ($phpStrStage as $path => $varValuePairs) {
        if (!is_readable($path)) {
            $errors[] = "config_writer: cannot read $path; PHP-string edits skipped";
            error_log("config_writer: cannot read $path; "
                . count($varValuePairs) . " PHP-string edits skipped");
            continue;
        }
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            $errors[] = "config_writer: file() failed for $path; PHP-string edits skipped";
            error_log("config_writer: file() failed for $path; "
                . count($varValuePairs) . " PHP-string edits skipped");
            continue;
        }

        foreach ($varValuePairs as $varName => $value) {
            // Match column-0 `$varName` followed by optional whitespace
            // then `=`. preg_quote is belt-and-braces — the var name is
            // already validated to /^[A-Za-z_][A-Za-z0-9_]*$/ by
            // config_writer_stage_php_string().
            $pattern = '/^\$' . preg_quote($varName, '/') . '\s*=/';
            $applied = false;
            foreach ($lines as $i => $line) {
                if (preg_match($pattern, $line)) {
                    // Escape value for a PHP single-quoted string
                    // literal: only `\` and `'` are special inside
                    // `'...'`. The two-char mask "\\'" tells
                    // addcslashes() to backslash-escape both:
                    //   `\` → `\\`  (first char of the mask)
                    //   `'` → `\'`  (second char of the mask)
                    // The result is parseable PHP that decodes back
                    // to the original $value bytes — so attacker
                    // bytes are stored as data, never executed.
                    $escaped = addcslashes($value, "\\'");
                    $lines[$i] = '$' . $varName . "='" . $escaped . "';";
                    $applied = true;
                    break;
                }
            }
            if (!$applied) {
                error_log("config_writer: $path has no \$$varName= line; PHP-string edit skipped");
            }
        }

        $err = _config_writer_install_atomic(
            $path,
            implode("\n", $lines) . "\n"
        );
        if ($err !== null) {
            $errors[] = $err;
            error_log($err);
        }
    }

    // Pass 3 — privileged flat key=value edits (root-only files).
    // Same column-0 `key=` semantics as pass 1, but the read step
    // uses `sudo cat` so we can service mode-600 root:root paths,
    // and the install mode is 600 not 644.
    foreach ($privStage as $path => $kvPairs) {
        $rc = 0;
        $out = array();
        // sudo -n: never prompt — fail loudly if sudoers ever changes.
        // Output is the file content; stderr captured separately so a
        // sudo / cat failure doesn't poison the parsed lines.
        exec('sudo -n cat ' . escapeshellarg($path) . ' 2>/dev/null',
             $out, $rc);
        if ($rc !== 0) {
            $errors[] = "config_writer: sudo cat exit=$rc for $path; privileged edits skipped";
            error_log("config_writer: sudo cat exit=$rc for $path; "
                . count($kvPairs) . " privileged edits skipped");
            continue;
        }
        $lines = $out;

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
            if (!$applied) {
                error_log("config_writer: $path has no '$key=' line; privileged edit skipped");
            }
        }

        $err = _config_writer_install_atomic(
            $path,
            implode("\n", $lines) . "\n",
            '600'
        );
        if ($err !== null) {
            $errors[] = $err;
            error_log($err);
        }
    }

    if ($manageMount) {
        system('sudo mount -o remount,ro /');
    }

    // Clear all stages so a subsequent commit() call doesn't
    // re-apply already-applied edits.
    $GLOBALS['__config_writer_stage'] = array();
    $GLOBALS['__config_writer_stage_phpstr'] = array();
    $GLOBALS['__config_writer_stage_priv'] = array();

    return $errors;
}
