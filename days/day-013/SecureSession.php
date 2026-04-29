<?php
/**
 * Day 13: SecureSession — Reusable Secure Session Management
 *
 * Covers:
 * - CWE-384: Session Fixation prevention via session_regenerate_id()
 * - CWE-1004: Cookie without HttpOnly flag
 * - CWE-614:  Cookie without Secure flag
 * - Idle timeout + session anomaly detection
 */

declare(strict_types=1);

class SecureSession
{
    private const IDLE_TIMEOUT = 1800; // 30 minutes

    /**
     * Initialize PHP session with hardened settings.
     * Must be called BEFORE any output.
     */
    public static function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return; // already started
        }

        // ✅ Cookie-only sessions: reject PHPSESSID in URL
        ini_set('session.use_only_cookies', '1');

        // ✅ Reject session IDs not created by this server
        ini_set('session.use_strict_mode', '1');

        // ✅ JS cannot read the session cookie (blocks XSS-based cookie theft)
        ini_set('session.cookie_httponly', '1');

        // ✅ Cookie only sent over HTTPS
        ini_set('session.cookie_secure', '1');

        // ✅ CSRF protection — cookie not sent in cross-site requests
        ini_set('session.cookie_samesite', 'Strict');

        // ✅ Short idle timeout
        ini_set('session.gc_maxlifetime', (string) self::IDLE_TIMEOUT);

        session_start();
    }

    /**
     * Call immediately after verifying login credentials.
     * Prevents session fixation (CWE-384).
     *
     * @param int    $userId  Authenticated user's ID
     * @param string $role    User's role (e.g., 'user', 'admin')
     */
    public static function elevate(int $userId, string $role): void
    {
        self::start();

        // ✅ Regenerate session ID — old session file is deleted
        // This invalidates any session ID the attacker may have planted
        session_regenerate_id(true);

        $_SESSION['user_id']  = $userId;
        $_SESSION['role']     = $role;       // role stored SERVER-SIDE only
        $_SESSION['created']  = time();
        $_SESSION['ip']       = self::getClientIp();
        $_SESSION['ua']       = $_SERVER['HTTP_USER_AGENT'] ?? '';
    }

    /**
     * Require an authenticated session. Redirects to /login if invalid.
     *
     * @param string $requiredRole  If set, also check that role matches
     */
    public static function requireAuth(string $requiredRole = ''): void
    {
        self::start();

        // Check session exists
        if (empty($_SESSION['user_id'])) {
            self::redirectToLogin('no_session');
        }

        // Idle timeout check
        if (time() - ($_SESSION['created'] ?? 0) > self::IDLE_TIMEOUT) {
            self::destroy();
            self::redirectToLogin('timeout');
        }

        // Optional: detect session anomaly (IP change)
        if (!empty($_SESSION['ip']) && $_SESSION['ip'] !== self::getClientIp()) {
            self::destroy();
            self::redirectToLogin('anomaly');
        }

        // Role check
        if ($requiredRole !== '' && ($_SESSION['role'] ?? '') !== $requiredRole) {
            http_response_code(403);
            exit('Access denied');
        }
    }

    /**
     * Destroy session on logout. Unsets all data and deletes the cookie.
     */
    public static function destroy(): void
    {
        self::start();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'],
                $params['domain'],
                $params['secure'],
                $params['httponly']
            );
        }
        session_destroy();
    }

    /**
     * Get current user ID from session.
     */
    public static function userId(): ?int
    {
        return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
    }

    /**
     * Get current user role from session (server-side only).
     */
    public static function role(): ?string
    {
        return $_SESSION['role'] ?? null;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Get client IP, only trusting forwarded headers from known proxies.
     */
    private static function getClientIp(): string
    {
        // ✅ Add your actual load balancer / proxy IPs here
        $trustedProxies = ['10.0.0.1', '10.0.0.2'];
        $remoteAddr     = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        if (in_array($remoteAddr, $trustedProxies, true)) {
            $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
            $ips = array_map('trim', explode(',', $forwarded));
            $clientIp = filter_var($ips[0], FILTER_VALIDATE_IP);
            return $clientIp ?: $remoteAddr;
        }

        // ✅ Default: trust TCP socket address only
        return $remoteAddr;
    }

    private static function redirectToLogin(string $reason): never
    {
        header('Location: /login?reason=' . urlencode($reason));
        exit;
    }
}

// ===================================================
// USAGE EXAMPLE
// ===================================================

// On login page (after verifying credentials):
// SecureSession::elevate($user['id'], $user['role']);
// header('Location: /dashboard'); exit;

// On protected pages:
// SecureSession::requireAuth();
// or for role-specific pages:
// SecureSession::requireAuth('admin');

// Accessing session data:
// $currentUserId = SecureSession::userId();
// $currentRole   = SecureSession::role();

// ===================================================
// SECURE COOKIE HELPER (non-session cookies)
// ===================================================

/**
 * Set a non-session cookie with all security flags applied.
 * ✅ NEVER store roles, auth state, or permissions in cookies.
 */
function setSecureCookie(string $name, string $value, int $ttl = 3600): void
{
    setcookie($name, $value, [
        'expires'  => time() + $ttl,
        'path'     => '/',
        'domain'   => '',        // current domain only
        'secure'   => true,      // HTTPS only
        'httponly' => true,      // no JS access
        'samesite' => 'Strict',  // CSRF protection
    ]);
}
