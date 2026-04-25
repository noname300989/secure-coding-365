<?php

/**
 * ChallengeBootstrap.php — Mini Challenge Solution Reference
 *
 * Scenario: You have a legacy PHP app on shared hosting.
 * No root access. You can only use .htaccess and ini_set().
 *
 * TASK: Meaningfully improve PHP security without touching php.ini
 *
 * ─────────────────────────────────────────────────────────
 * PART 1: .htaccess (Apache + mod_php)
 * ─────────────────────────────────────────────────────────
 * Place this .htaccess file in your web root:
 *
 *   # Disable error display
 *   php_flag  display_errors        Off
 *   php_flag  display_startup_errors Off
 *   php_value log_errors            On
 *   php_flag  expose_php            Off
 *
 *   # Session security
 *   php_flag  session.cookie_httponly 1
 *   php_flag  session.cookie_secure   1
 *   php_flag  session.use_strict_mode 1
 *   php_value session.cookie_samesite Strict
 *   php_flag  session.use_only_cookies 1
 *
 *   # Resource limits
 *   php_value memory_limit           128M
 *   php_value max_execution_time     30
 *
 * ─────────────────────────────────────────────────────────
 * LIMITATION: .htaccess only works with mod_php (Apache).
 * It does NOT work with PHP-FPM (the modern default).
 * For PHP-FPM, you need php-fpm pool config or php.ini.
 * ─────────────────────────────────────────────────────────
 *
 * BONUS ANSWER: When does ini_set() NOT work?
 *
 * PHP settings have changeable modes:
 *   PHP_INI_ALL    — Can be changed anywhere (php.ini, .htaccess, ini_set())
 *   PHP_INI_USER   — Can be changed in user scripts and .user.ini
 *   PHP_INI_PERDIR — Can be changed in php.ini, httpd.conf, .htaccess
 *   PHP_INI_SYSTEM — Can ONLY be changed in php.ini or httpd.conf (NOT ini_set()!)
 *
 * Settings you CANNOT change with ini_set():
 *   - disable_functions       → PHP_INI_SYSTEM
 *   - disable_classes         → PHP_INI_SYSTEM
 *   - expose_php              → PHP_INI_SYSTEM
 *   - allow_url_include       → PHP_INI_SYSTEM (PHP 7.4+)
 *   - open_basedir            → PHP_INI_SYSTEM
 *
 * This means: even if you call ini_set('disable_functions', ''), it has NO EFFECT.
 * These critical security settings MUST be set in php.ini or httpd.conf.
 */

declare(strict_types=1);

// ─────────────────────────────────────────────────────────────────────────────
// PART 2: bootstrap.php — security hardening without root
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Apply security settings using ini_set() where possible.
 * Note: PHP_INI_SYSTEM settings (disable_functions, expose_php, open_basedir)
 * CANNOT be changed here — they require php.ini.
 */
function applySecuritySettings(): void
{
    // Error handling — ini_set() works for these (PHP_INI_ALL)
    ini_set('display_errors', '0');
    ini_set('display_startup_errors', '0');
    ini_set('log_errors', '1');
    // Note: error_log path may not be changeable on shared hosting

    // Resource limits (PHP_INI_ALL — changeable)
    ini_set('memory_limit', '128M');
    ini_set('max_execution_time', '30');
}

/**
 * Configure session with secure cookie parameters.
 * MUST be called before session_start()!
 */
function configureSecureSession(): void
{
    // session_set_cookie_params() overrides php.ini session settings at runtime
    session_set_cookie_params([
        'lifetime' => 1800,           // 30 minutes
        'path'     => '/',
        'domain'   => '',             // Current domain only
        'secure'   => true,           // HTTPS only
        'httponly' => true,           // No JS access (blocks XSS cookie theft)
        'samesite' => 'Strict',       // No cross-site cookie sending (blocks CSRF)
    ]);

    // These ini_set calls work (PHP_INI_ALL):
    ini_set('session.use_only_cookies', '1');    // No session ID in URLs
    ini_set('session.use_strict_mode', '1');      // Reject unknown session IDs (anti-fixation)
    ini_set('session.gc_maxlifetime', '1800');    // Match cookie lifetime
}

/**
 * Install a secure global exception handler.
 * Logs full details internally, shows generic message to users.
 */
function installSecureExceptionHandler(): void
{
    set_exception_handler(function (Throwable $e): void {
        // Generate a correlation ID for support/debugging
        $correlationId = bin2hex(random_bytes(8));

        // Log FULL exception details to server error log (not visible to users)
        error_log(sprintf(
            '[UNHANDLED EXCEPTION] [%s] %s: %s in %s:%d | Trace: %s',
            $correlationId,
            get_class($e),
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
            $e->getTraceAsString()
        ));

        // Clear any output already sent (prevent partial page + error leakage)
        if (ob_get_level() > 0) {
            ob_clean();
        }

        // Generic HTTP 500 response — no internal details!
        http_response_code(500);
        header('Content-Type: text/html; charset=UTF-8');

        echo sprintf(
            '<h1>Something went wrong</h1><p>An unexpected error occurred. Reference ID: <code>%s</code></p>',
            htmlspecialchars($correlationId, ENT_QUOTES, 'UTF-8')
        );

        exit(1);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap sequence — call this at the very top of index.php
// ─────────────────────────────────────────────────────────────────────────────

applySecuritySettings();
configureSecureSession();
installSecureExceptionHandler();

// Now safe to start the session
session_start();

/*
 * IMPORTANT REMINDERS:
 *
 * 1. ini_set('disable_functions', ...) does NOTHING — PHP_INI_SYSTEM only.
 *    Ask your hosting provider to disable exec/system/shell_exec in php.ini.
 *
 * 2. ini_set('expose_php', '0') does NOTHING — PHP_INI_SYSTEM only.
 *    The version header will still be sent unless set in php.ini.
 *
 * 3. ini_set('open_basedir', ...) is a PHP_INI_SYSTEM setting and may be
 *    restricted. Some hosts allow it in .user.ini but not ini_set().
 *
 * 4. On shared hosting with PHP-FPM, .htaccess php_flag directives are IGNORED.
 *    Use .user.ini instead (PHP scans for this file in each directory).
 *
 * 5. The best solution is always to advocate for proper php.ini configuration
 *    and move away from shared hosting for production applications.
 */
