<?php

declare(strict_types=1);

/**
 * SecurityConfigCheck.php
 *
 * Runtime verification of critical PHP security settings.
 * Call during application bootstrap to ensure settings haven't been
 * overridden by .htaccess, ini_set(), or hosting provider defaults.
 *
 * IMPORTANT: Never expose this check's output to users.
 * Log issues privately and throw a generic error message.
 */

class PhpSecurityConfigException extends RuntimeException {}

function assertSecurePhpConfig(): void
{
    $issues = [];
    $criticals = [];

    // ── Information Disclosure ──────────────────────────────────────────────

    if (filter_var(ini_get('expose_php'), FILTER_VALIDATE_BOOLEAN)) {
        $issues[] = 'WARNING: expose_php=On — PHP version leaked in HTTP headers';
    }

    // ── Error Handling ──────────────────────────────────────────────────────

    if (filter_var(ini_get('display_errors'), FILTER_VALIDATE_BOOLEAN)) {
        $criticals[] = 'CRITICAL: display_errors=On — errors visible to all users! (CWE-209)';
    }

    if (filter_var(ini_get('display_startup_errors'), FILTER_VALIDATE_BOOLEAN)) {
        $issues[] = 'WARNING: display_startup_errors=On — startup errors shown to users';
    }

    if (!filter_var(ini_get('log_errors'), FILTER_VALIDATE_BOOLEAN)) {
        $issues[] = 'WARNING: log_errors=Off — errors not being recorded anywhere';
    }

    // ── Dangerous Functions ─────────────────────────────────────────────────

    $disabledFunctions = ini_get('disable_functions');
    $requiredDisabled = ['exec', 'system', 'shell_exec', 'passthru', 'proc_open'];
    foreach ($requiredDisabled as $fn) {
        if (!str_contains($disabledFunctions, $fn)) {
            $issues[] = "WARNING: Function '$fn' is not disabled — post-exploitation risk";
        }
    }

    // ── Remote File Inclusion ───────────────────────────────────────────────

    if (filter_var(ini_get('allow_url_include'), FILTER_VALIDATE_BOOLEAN)) {
        $criticals[] = 'CRITICAL: allow_url_include=On — Remote File Inclusion attacks possible!';
    }

    if (filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
        $issues[] = 'MEDIUM: allow_url_fopen=On — PHP can fetch remote URLs (SSRF risk)';
    }

    // ── Session Security ────────────────────────────────────────────────────

    if (!filter_var(ini_get('session.cookie_httponly'), FILTER_VALIDATE_BOOLEAN)) {
        $criticals[] = 'HIGH: session.cookie_httponly=Off — XSS can steal session cookies!';
    }

    if (!filter_var(ini_get('session.cookie_secure'), FILTER_VALIDATE_BOOLEAN)) {
        $issues[] = 'HIGH: session.cookie_secure=Off — session cookie sent over HTTP!';
    }

    if (!filter_var(ini_get('session.use_strict_mode'), FILTER_VALIDATE_BOOLEAN)) {
        $issues[] = 'MEDIUM: session.use_strict_mode=Off — session fixation attacks possible';
    }

    if (!filter_var(ini_get('session.use_only_cookies'), FILTER_VALIDATE_BOOLEAN)) {
        $issues[] = 'HIGH: session.use_only_cookies=Off — session ID may appear in URLs!';
    }

    // ── Resource Limits ─────────────────────────────────────────────────────

    $memoryLimit = ini_get('memory_limit');
    if ($memoryLimit === '-1') {
        $issues[] = 'MEDIUM: memory_limit=-1 (unlimited) — Denial of Service risk';
    }

    $maxExecTime = (int) ini_get('max_execution_time');
    if ($maxExecTime > 60 || $maxExecTime === 0) {
        $issues[] = "MEDIUM: max_execution_time={$maxExecTime}s is too high or unlimited — slow DoS risk";
    }

    // ── Report ──────────────────────────────────────────────────────────────

    $allIssues = array_merge($criticals, $issues);

    if (!empty($allIssues)) {
        $logMessage = '[PHP SECURITY MISCONFIGURATION] ' . implode(' | ', $allIssues);

        // Log full details to server error log (not visible to users)
        error_log($logMessage);

        // If there are critical issues, halt the application
        if (!empty($criticals)) {
            // Generic message to user — never expose internal details!
            throw new PhpSecurityConfigException(
                'Application startup failed due to a configuration error. Please contact the administrator.'
            );
        }

        // Non-critical issues: log but continue (or throw in strict mode)
        // In a real app, you might send an alert to your security team here
    }
}

// =============================================================================
// Example Usage (in your bootstrap/index.php)
// =============================================================================

/*
// index.php or bootstrap.php:

require_once __DIR__ . '/SecurityConfigCheck.php';

try {
    assertSecurePhpConfig();
} catch (PhpSecurityConfigException $e) {
    // Log with full context internally
    error_log('[STARTUP FAILURE] Security check failed: ' . $e->getMessage());

    // Show only generic message to user
    http_response_code(500);
    echo 'Service temporarily unavailable. Please try again later.';
    exit(1);
}
*/
