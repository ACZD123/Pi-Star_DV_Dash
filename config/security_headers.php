<?php
/**
 * Security headers for the Pi-Star Dashboard.
 *
 * Centralises Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
 * X-XSS-Protection, Referrer-Policy, Permissions-Policy, and HSTS so every
 * dashboard entry-point sets the same baseline.
 *
 * Three flavours are provided because dashboard pages fall into three
 * distinct categories:
 *
 *   - {@see setSecurityHeaders()}                   — top-level pages
 *     (index, admin, configure, editors). Locks frame ancestors and frame-src
 *     to same-origin to prevent the page being framed by a hostile site.
 *
 *   - {@see setEmbeddableSecurityHeaders()}         — AJAX-loaded partials
 *     (last-heard list, local TX, mode info, etc.). Same CSP minus the frame
 *     restrictions, because the partial is itself loaded into a parent page
 *     via $.load() and would otherwise refuse to embed.
 *
 *   - {@see setSecurityHeadersAllowDifferentPorts()} — pages that iframe
 *     services on different ports of the same host (e.g. shellinabox SSH on
 *     a non-80 port). Adds frame-src for the same hostname on any port.
 *
 * HSTS is only emitted when the request is over HTTPS (direct or via an
 * upstream proxy reporting X-Forwarded-Proto). All three functions are
 * idempotent and bail early if headers have already been sent.
 *
 * The CSP intentionally allows 'unsafe-inline' for both scripts and styles
 * because the dashboard inlines large amounts of JS and inline `style="…"`
 * attributes; tightening this would require a much larger refactor.
 */

/**
 * Detect whether the current request is being served over HTTPS.
 *
 * Checks both direct indicators ($_SERVER['HTTPS'], port 443) and proxy
 * headers (X-Forwarded-Proto, X-Forwarded-SSL) so we still detect HTTPS
 * correctly when sitting behind a TLS-terminating proxy.
 *
 * @return bool True if the request is over HTTPS, false otherwise.
 */
function isHttps() {
    // Check standard HTTPS indicators
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }
    if (!empty($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443) {
        return true;
    }
    // Check for proxy/load balancer headers
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
        return true;
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on') {
        return true;
    }
    return false;
}

/**
 * Set full security headers for non-embeddable pages
 * Use for: Admin pages, configuration editors, main entry points
 */
function setSecurityHeaders() {
    // Only set headers if they haven't been sent yet
    if (!headers_sent()) {
        $isHttps = isHttps();

        header("X-Frame-Options: SAMEORIGIN");
        header("X-Content-Type-Options: nosniff");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

        // Build CSP based on protocol
        // Allow external images via both http: and https: since we can't control external links
        $imgSrc = $isHttps ? "'self' data: https:" : "'self' data: http: https:";

        $csp = "default-src 'self'; " .
               "script-src 'self' 'unsafe-inline'; " .
               "style-src 'self' 'unsafe-inline'; " .
               "img-src {$imgSrc}; " .
               "connect-src 'self'; " .
               "frame-ancestors 'self'";

        header("Content-Security-Policy: " . $csp);

        // Only add HSTS if served over HTTPS
        if ($isHttps) {
            // HSTS: Force HTTPS for 1 year, but don't include subdomains (might be on local network)
            header("Strict-Transport-Security: max-age=31536000");
        }
    }
}

/**
 * Set embeddable security headers for display components
 * Use for: Status displays, last heard lists, info panels meant to be embeddable
 */
function setEmbeddableSecurityHeaders() {
    // Only set headers if they haven't been sent yet
    if (!headers_sent()) {
        $isHttps = isHttps();

        // Note: X-Frame-Options omitted to allow embedding
        header("X-Content-Type-Options: nosniff");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

        // Build CSP based on protocol
        $imgSrc = $isHttps ? "'self' data: https:" : "'self' data: http: https:";

        $csp = "default-src 'self'; " .
               "script-src 'self' 'unsafe-inline'; " .
               "style-src 'self' 'unsafe-inline'; " .
               "img-src {$imgSrc}; " .
               "connect-src 'self'";

        header("Content-Security-Policy: " . $csp);

        // Only add HSTS if served over HTTPS
        if ($isHttps) {
            header("Strict-Transport-Security: max-age=31536000");
        }
    }
}

/**
 * Set security headers for pages that embed content from different ports on same host
 *
 * This allows iframes from the same hostname but different ports
 */
function setSecurityHeadersAllowDifferentPorts() {
    // Only set headers if they haven't been sent yet
    if (!headers_sent()) {
        $isHttps = isHttps();

        header("X-Frame-Options: SAMEORIGIN");
        header("X-Content-Type-Options: nosniff");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

        // Get current hostname for frame-src
        $hostname = $_SERVER['HTTP_HOST'];
        // Remove port if present to get just the hostname
        $hostnameOnly = preg_replace('/:\d+$/', '', $hostname);

        // Build CSP that allows frames from same hostname on any port
        $imgSrc = $isHttps ? "'self' data: https:" : "'self' data: http: https:";

        // Allow frames from same hostname with any port (for shellinabox, etc.)
        $csp = "default-src 'self'; " .
               "script-src 'self' 'unsafe-inline'; " .
               "style-src 'self' 'unsafe-inline'; " .
               "img-src {$imgSrc}; " .
               "connect-src 'self'; " .
               "frame-src 'self' http://{$hostnameOnly}:* https://{$hostnameOnly}:*; " .
               "frame-ancestors 'self'";

        header("Content-Security-Policy: " . $csp);

        // Only add HSTS if served over HTTPS
        if ($isHttps) {
            header("Strict-Transport-Security: max-age=31536000");
        }
    }
}
