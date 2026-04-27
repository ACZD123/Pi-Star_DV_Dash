<?php
/**
 * CSRF (Cross-Site Request Forgery) protection primitive for the
 * Pi-Star dashboard.
 *
 * Threat model
 * ============
 *
 * The dashboard sits behind Apache HTTP Basic Auth on a LAN. The
 * authenticated administrator's browser will automatically attach
 * the basic-auth credential to ANY request the browser sends to the
 * dashboard's host — including requests triggered by a malicious
 * page open in another tab. Without CSRF protection, that hostile
 * page can POST to e.g. `/admin/power.php` and reboot the device,
 * or POST a full configuration to `/admin/configure.php`, simply
 * because the user's browser is sitting on cached basic-auth.
 *
 * The mitigation: every state-changing POST handler MUST verify
 * that the request carries a server-issued, session-scoped token
 * the attacker cannot read (same-origin policy prevents the hostile
 * page from reading the dashboard's HTML to extract it).
 *
 * Public API
 * ==========
 *
 *   csrf_token()   -> string  (64 hex chars; idempotent within a session)
 *   csrf_field()   -> echoes a hidden <input> tag for forms
 *   csrf_verify()  -> dies with HTTP 403 if the POSTed token is missing
 *                     or invalid; returns silently otherwise
 *
 * Usage
 * =====
 *
 * In a top-level GET-rendered page that contains a POST form:
 *
 *     require_once $_SERVER['DOCUMENT_ROOT'] . '/config/csrf.php';
 *     ...
 *     <form method="post" action="...">
 *     <?php csrf_field(); ?>
 *     ...
 *     </form>
 *
 * In the matching POST handler (top of the file, before any state
 * change):
 *
 *     require_once $_SERVER['DOCUMENT_ROOT'] . '/config/csrf.php';
 *     if ($_SERVER['REQUEST_METHOD'] === 'POST') {
 *         csrf_verify();
 *     }
 *
 * Design notes
 * ============
 *
 *   - One token per session, reused across forms. Simpler retrofit
 *     than per-form tokens; no UX downside (the attacker still can't
 *     read the token, which is what matters). The token rotates
 *     when the session itself rotates (typically: browser closed,
 *     basic-auth re-prompted, or `session_regenerate_id()` called
 *     elsewhere).
 *
 *   - Token = `bin2hex(random_bytes(32))` -> 64 hex chars (256 bits
 *     of entropy). `random_bytes()` is PHP 7.0+ and uses the
 *     OS CSPRNG (`/dev/urandom` on Linux). PHP 7.0 is this codebase's
 *     stated floor, so no fallback needed.
 *
 *   - Verification uses `hash_equals()` (PHP 5.6+) for constant-
 *     time comparison. This is overkill for a hex-vs-hex comparison
 *     against a 256-bit secret, but costs nothing and removes any
 *     theoretical timing-leak class.
 *
 *   - Failure mode (HTTP 403): write a minimal, self-contained HTML
 *     page rather than a JSON blob. The dashboard's forms post
 *     directly and the user lands on the response body in their
 *     browser — they need to understand what happened.
 *
 *   - We deliberately do NOT call session_regenerate_id() on each
 *     request. Several existing pages (admin/update.php,
 *     admin/calibration.php, admin/live_modem_log.php) store
 *     log-tail offsets in $_SESSION across many AJAX requests; a
 *     mid-session ID rotation would lose those offsets and break
 *     the live log tails.
 *
 *   - GET requests are NOT verified. CSRF protection only applies
 *     to state-changing requests, and the dashboard's idempotent
 *     read pages are POST-free by convention.
 *
 *   - Session-cookie hardening. We set HttpOnly + SameSite=Lax on
 *     every issued PHPSESSID, and Secure conditionally when the
 *     request is HTTPS (via isHttps() in security_headers.php —
 *     covers direct TLS to nginx AND reverse-proxy / Cloudflare
 *     terminations that forward via X-Forwarded-Proto). See
 *     {@see _csrf_set_cookie_params()}.
 */

require_once $_SERVER['DOCUMENT_ROOT'] . '/config/security_headers.php';

/**
 * Configure the PHPSESSID cookie's flags for hardened delivery.
 *
 * Must be called BEFORE session_start(); has no effect once the
 * session is active. Sets:
 *
 *   HttpOnly  — always. Blocks document.cookie access from JS, so
 *               a future XSS in any rendered page can't read the
 *               session ID. Defence in depth alongside the input
 *               escaping work in the rest of the security pass.
 *
 *   SameSite=Lax — always. Browser stops sending the cookie on
 *               cross-site subresource fetches and cross-site POSTs;
 *               top-level navigation (clicking a bookmark, following
 *               a same-origin redirect) still carries it, so UX
 *               doesn't change. Belt-and-braces with the existing
 *               CSRF-token check.
 *
 *   Secure    — conditional on isHttps(). UNCONDITIONALLY setting
 *               Secure would invalidate the cookie for the (large)
 *               population of operators on plain-HTTP LAN access
 *               and silently break CSRF protection. isHttps() also
 *               returns true for X-Forwarded-Proto: https — so
 *               operators behind Cloudflare / a reverse proxy /
 *               Tailscale Funnel get the right Secure flag even
 *               though nginx itself only sees plain HTTP.
 *
 *               Trust caveat: an attacker who can talk directly
 *               to nginx on port 80 (bypassing the proxy) could
 *               spoof X-Forwarded-Proto and trick the dashboard
 *               into setting Secure on their own session. The
 *               consequence is the spoofer's cookie won't replay
 *               over plain HTTP — a self-DoS, not an escalation.
 *
 * PHP version handling. The samesite option was added to
 * session_set_cookie_params() in PHP 7.3 (the array form). On
 * 7.0..7.2 we fall back to the well-known path-suffix kludge:
 * appending `; SameSite=Lax` to the path argument. PHP doesn't
 * validate the path string — it concatenates verbatim into the
 * Set-Cookie header — and browsers parse `path=/; SameSite=Lax`
 * correctly because `;` terminates the path attribute. The
 * codebase floor is PHP 7.0; the production runtime is PHP 8.2.
 *
 * @return void
 */
function _csrf_set_cookie_params()
{
    $secure = function_exists('isHttps') ? isHttps() : false;
    if (PHP_VERSION_ID >= 70300) {
        // Modern array form. Available since PHP 7.3.
        @session_set_cookie_params(array(
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ));
    } else {
        // PHP 7.0..7.2: no native samesite support. The path-suffix
        // kludge is the documented workaround — see PHP RFC for
        // 7.3's array form, where this is acknowledged as the
        // pre-7.3 idiom. lifetime/path/domain/secure/httponly here
        // mirror the array values above.
        @session_set_cookie_params(0, '/; SameSite=Lax', '', $secure, true);
    }
}

/**
 * Ensure a session is started. Idempotent.
 *
 * Several dashboard pages already call `session_start()` for their
 * own state (log offsets, etc.), so this primitive must coexist
 * gracefully with prior `session_start()` calls. PHP_SESSION_ACTIVE
 * is the canonical guard introduced in PHP 5.4.
 */
function csrf_session_start()
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        // Pi-Star ships with `session.gc_probability=0` AND
        // /var/lib/php/sessions mounted as a 64KB tmpfs (per
        // /etc/fstab in the OS image). With CSRF, every dashboard
        // visit creates a session file, and without automatic GC
        // those accumulate until reboot — at which point the tmpfs
        // fills (~15 sessions) and session_start() starts failing
        // with "No space left on device", silently breaking CSRF.
        //
        // Force GC at session-start time by bumping the probability
        // ratio to 1/1. PHP runs GC itself during session_start when
        // (gc_probability / gc_divisor) > random — at 1/1 that's
        // every call, but only for THIS request's session_start.
        // Cost: a tmpfs `glob` + a few `unlink`s, microseconds.
        // The @-suppression handles hosts that disallow ini_set on
        // these keys; failure just means we fall back to PHP's
        // default behaviour, same as before this fix.
        //
        // session_gc() (PHP 7.1+) would be cleaner but the codebase
        // targets PHP 7.0. ini_set works on every supported version.
        if ((int)ini_get('session.gc_probability') === 0) {
            @ini_set('session.gc_probability', '1');
            @ini_set('session.gc_divisor', '1');
        }
        // gc_maxlifetime is intentionally NOT overridden here — we
        // defer to Pi-Star's stock /etc/php/*/fpm/php.ini value
        // (1440 s, matching PHP's own default). The dashboard's
        // AJAX-refreshing panels (lh.php, repeaterinfo.php, the
        // bm_links / tgif_links partials, etc.) do not load csrf.php,
        // so they don't update the session file's mtime — meaning the
        // session counts as "idle" from the moment csrf_verify() last
        // ran on a top-level page load, even while the dashboard is
        // visibly active in the operator's tab. Anything shorter than
        // ~24 min would routinely 403 BM-manager / TGIF-manager /
        // configure.php POSTs whenever the operator left the dashboard
        // tab open between page loads. tmpfs containment is the
        // pre-emptive prune below, not maxlifetime.
        //
        // Pi-Star's /var/lib/php/sessions tmpfs is sized 64 KB (per
        // /etc/fstab in the OS image) — about 15 session files at
        // a 4 KB tmpfs block each. csrf.php is only loaded behind
        // basic auth on /admin/*, so the only session-creators are
        // authenticated operators (whose browsers reuse one cookie =
        // one session) and tooling that hits the dashboard with
        // fresh cookie jars per request. The latter has filled the
        // tmpfs in practice; once full, session_start() fails with
        // "No space left on device" and CSRF silently breaks for
        // the operator — they get a 403 on the next form submit
        // because $_SESSION['csrf_token'] could not be persisted.
        //
        // Belt-and-braces safety net: cap the session directory at
        // 12 files BEFORE session_start() tries to write a new one.
        // GC alone won't help here because a burst of fresh-cookie
        // requests can fill the 64 KB tmpfs faster than gc_maxlifetime
        // expires anything. This pre-emptive prune deletes the
        // oldest sess_* files until 12 remain, leaving ~3 slots of
        // headroom under the ~15-file tmpfs cap.
        //
        // Best-effort: any failure here (permissions, missing dir,
        // glob/unlink errors) is silently ignored — session_start()
        // will still try and either succeed or fall through to the
        // existing failure-logging path below. Worst case for an
        // evicted session is an operator gets a 403 on the next
        // form submit and a page reload re-issues a token, which
        // is far better than the disk-full failure this guards
        // against.
        $sessSaveDir = (string)@ini_get('session.save_path');
        if ($sessSaveDir !== '') {
            $sessFiles = @glob($sessSaveDir . '/sess_*');
            if (is_array($sessFiles) && count($sessFiles) > 12) {
                usort($sessFiles, function ($a, $b) {
                    return (int)@filemtime($a) - (int)@filemtime($b);
                });
                $sessExcess = count($sessFiles) - 12;
                for ($i = 0; $i < $sessExcess; $i++) {
                    @unlink($sessFiles[$i]);
                }
            }
        }
        // Harden the PHPSESSID cookie flags BEFORE session_start()
        // emits the Set-Cookie header. See _csrf_set_cookie_params()
        // for the per-flag rationale.
        _csrf_set_cookie_params();
        // Suppress notices about headers already sent — some
        // dashboard pages emit output before this is reached.
        // The session won't be usable in that scenario, but
        // failing closed (csrf_verify rejects the POST) is the
        // correct outcome. Log the underlying cause so a future
        // maintainer who accidentally reorders requires above an
        // echo can see why their POSTs started 403'ing.
        if (@session_start() === false) {
            error_log('csrf_session_start: session_start() failed '
                . '(headers already sent? require_once order?)');
        }
    }
}

/**
 * Return the session's CSRF token, issuing a fresh one on first
 * call within a session.
 *
 * @return string 64-character hex string.
 */
function csrf_token()
{
    csrf_session_start();
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Echo a hidden form input carrying the CSRF token.
 *
 * Place INSIDE the `<form>` element, before the submit button.
 * Output is htmlspecialchars-safe: a hex string never contains
 * any character that needs escaping, but we encode anyway as a
 * defence against future changes to the token format.
 *
 * For sites that build form HTML into a string variable rather
 * than echoing inline, see {@see csrf_field_html()}.
 */
function csrf_field()
{
    echo csrf_field_html();
}

/**
 * Return a hidden form input carrying the CSRF token, as a
 * string. Useful for code that accumulates form HTML into a
 * `$output` variable (e.g. wifi.php's wpa_conf form) where an
 * `echo` mid-expression doesn't compose.
 *
 * @return string The hidden-input HTML.
 */
function csrf_field_html()
{
    $tok = htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8');
    return '<input type="hidden" name="csrf_token" value="' . $tok . '" />';
}

/**
 * Verify the POSTed CSRF token. On mismatch, emit HTTP 403 and exit.
 *
 * Call this from EVERY state-changing POST handler before any side
 * effect (file write, system call, session mutation, etc.). It is
 * a no-op for GET / HEAD / OPTIONS requests — those are read-only
 * by convention in this dashboard.
 *
 * The function does not return on failure: it sets the response
 * code, prints a minimal HTML error page, and calls exit().
 */
function csrf_verify()
{
    // Bootstrap the session up front, even on GET, so the
    // Set-Cookie header gets emitted before any HTML output.
    // csrf_field() (called inside the page's <form> tags) is
    // lazy and may not run until well after output has started,
    // so without an early csrf_verify() call sites that don't
    // already have their own pre-output session_start() (most
    // pages — power.php is the exception) never get a session
    // cookie. Without a cookie the GET-issued token has no way
    // to reach the POST handler.
    //
    // Pages should call csrf_verify() near the top of the file,
    // BEFORE any output. On GET it bootstraps the session and
    // returns; on POST it bootstraps, validates, and either
    // returns silently or emits 403 + exit().
    csrf_session_start();

    if (!isset($_SERVER['REQUEST_METHOD']) ||
        $_SERVER['REQUEST_METHOD'] !== 'POST') {
        // Only POST is gated — GET pages render the token via
        // csrf_field() and don't need verification.
        return;
    }

    $expected = isset($_SESSION['csrf_token']) ? $_SESSION['csrf_token'] : '';
    $supplied = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';

    // Reject if either side is empty OR not a 64-char hex string.
    // Reject empty BEFORE hash_equals to avoid the (harmless but
    // ugly) constant-time-compare-against-empty-string case.
    if (!is_string($expected) || strlen($expected) !== 64 ||
        !is_string($supplied) || strlen($supplied) !== 64 ||
        !hash_equals($expected, $supplied)) {
        // Best-effort log line for the operator. The remote IP is
        // typically a LAN address but worth recording in case a
        // rogue device is fingerprinted by repeated 403s.
        $remote = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '?';
        $uri    = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '?';
        error_log("csrf_verify: rejected POST from $remote to $uri");

        http_response_code(403);
        header('Content-Type: text/html; charset=utf-8');
        // Don't pollute browser history with this response.
        header('Cache-Control: no-store');
        // English-only by design: the dashboard's lang/ system
        // requires config/language.php, which reads /etc/pistar-release
        // and the gateway configs. Pulling that whole stack into an
        // error path that only fires under attack is disproportionate.
        echo '<!DOCTYPE html><html lang="en"><head>'
           . '<meta charset="utf-8" /><title>403 Forbidden</title></head>'
           . '<body><h1>403 Forbidden</h1>'
           . '<p>This request did not include a valid CSRF token. '
           . 'If you reached this page by clicking a link from another site, '
           . 'that other site may have been trying to perform an action on '
           . 'your behalf without your consent.</p>'
           . '<p>If you reached this page by submitting a form on the '
           . 'dashboard, your session may have expired. Reload the page '
           . 'and try again.</p>'
           . '</body></html>';
        exit;
    }

    // Token verified — strip it from $_POST so downstream handlers
    // that iterate $_POST (e.g. fulledit_bmapikey.php and
    // fulledit_dapnetapi.php's INI writers, which treat each top-
    // level POST key as an [INI section]) don't accidentally write
    // a stray `[csrf token]` block into /etc/<file>. Without this,
    // every successful submit on those editors prepended an empty
    // `[csrf token]` section to the saved config and rendered a
    // ghost table titled "csrf_token" on the response page.
    // Centralising the unset here means every current and future
    // POST handler is immune without needing to remember the dance.
    unset($_POST['csrf_token']);
}
