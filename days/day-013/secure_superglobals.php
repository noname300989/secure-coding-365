<?php
/**
 * Day 13: Arrays & Superglobals Security — SECURE EXAMPLES
 *
 * ✅ Production-safe superglobal handling patterns.
 *
 * Key principles:
 * - Always use filter_input() with explicit type + validation
 * - Never read roles/permissions from cookies (client-side)
 * - Regenerate session ID after every privilege change
 * - Only trust REMOTE_ADDR unless request comes from known proxy
 * - Set HttpOnly + Secure + SameSite on all cookies
 */

declare(strict_types=1);

// ===================================================
// 1. TYPED INPUT WITH filter_input()
// ===================================================

// ✅ Integer with range check — returns null if missing, false if invalid/out-of-range
$userId = filter_input(INPUT_GET, 'user_id', FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => PHP_INT_MAX]
]);
if ($userId === null || $userId === false) {
    http_response_code(400);
    exit('Invalid user ID');
}
// $userId is now a guaranteed positive integer — safe for parameterized queries

// ✅ Email validation
$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
if (!$email) {
    http_response_code(400);
    exit('Invalid email format');
}

// ✅ Sanitize + encode string for display
$search = filter_input(INPUT_GET, 'q', FILTER_DEFAULT) ?? '';
// Always encode for output context regardless of sanitization (Day 12!)
echo '<h1>Results for: ' . htmlspecialchars($search, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</h1>';

// ✅ URL validation with allowlist for redirect destination
$redirect    = filter_input(INPUT_GET, 'next', FILTER_VALIDATE_URL);
$allowedPaths = ['/dashboard', '/profile', '/settings'];
if ($redirect && in_array(parse_url($redirect, PHP_URL_PATH), $allowedPaths, true)) {
    header('Location: ' . $redirect);
} else {
    header('Location: /dashboard'); // safe default
}
exit;

// ===================================================
// 2. CENTRALIZED INPUT HELPERS
// ===================================================

/**
 * Read a validated integer from a superglobal input.
 * Returns null if missing or outside range.
 */
function inputInt(int $source, string $key, int $min = 1, int $max = PHP_INT_MAX): ?int {
    $val = filter_input($source, $key, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => $min, 'max_range' => $max]
    ]);
    return ($val !== null && $val !== false) ? $val : null;
}

/**
 * Read a trimmed string from a superglobal input.
 * Returns null if missing or exceeds $maxLen characters.
 */
function inputString(int $source, string $key, int $maxLen = 255): ?string {
    $val = filter_input($source, $key, FILTER_DEFAULT);
    if ($val === null || $val === false) {
        return null;
    }
    $val = trim($val);
    return mb_strlen($val) <= $maxLen ? $val : null;
}

// Usage examples:
$page   = inputInt(INPUT_GET, 'page', 1, 1000) ?? 1;
$search = inputString(INPUT_GET, 'q', 100) ?? '';

// ✅ filter_input_array() for reading multiple inputs at once
$inputs = filter_input_array(INPUT_GET, [
    'q'    => FILTER_DEFAULT,
    'page' => ['filter'  => FILTER_VALIDATE_INT,
               'options' => ['min_range' => 1, 'max_range' => 1000]],
]);
