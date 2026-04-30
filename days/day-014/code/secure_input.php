<?php
/**
 * SECURE: Typed, whitelist-based, fail-closed validation functions
 *
 * Design principles:
 * - Each function validates ONE type of data
 * - Returns typed value or null — null means REJECT
 * - Never returns "cleaned" strings that might bypass other checks
 * - Uses PHP's built-in filter_var() for correctness
 * - Functions are small, single-purpose, and unit-testable
 */

/**
 * Validate an integer within an optional range.
 *
 * @param mixed $value  Raw input (string from $_GET/$_POST or any type)
 * @param int   $min    Minimum allowed value (inclusive)
 * @param int   $max    Maximum allowed value (inclusive)
 * @return int|null     Typed integer on success, null on failure
 *
 * IMPORTANT: filter_var returns FALSE on failure, not null.
 * Always check === false, not just falsy — because 0 is a valid integer.
 */
function validate_int(
    mixed $value,
    int $min = PHP_INT_MIN,
    int $max = PHP_INT_MAX
): ?int {
    $filtered = filter_var($value, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => $min, 'max_range' => $max]
    ]);
    return ($filtered === false) ? null : (int) $filtered;
}

/**
 * Validate an email address using PHP's RFC-compliant filter.
 *
 * @param mixed $value  Raw input
 * @return string|null  Lowercase normalised email or null
 */
function validate_email(mixed $value): ?string
{
    if (!is_string($value)) return null;
    $email = filter_var(trim($value), FILTER_VALIDATE_EMAIL);
    return ($email === false) ? null : mb_strtolower($email);
}

/**
 * Validate a string against a strict whitelist regex pattern.
 *
 * Default pattern: alphanumeric + underscore + hyphen, 1–64 chars.
 * Change $pattern for different slug formats.
 *
 * @param mixed  $value    Raw input
 * @param string $pattern  PCRE regex with anchors (^ and $)
 * @return string|null     Validated string or null
 */
function validate_slug(
    mixed $value,
    string $pattern = '/^[a-zA-Z0-9_-]{1,64}$/'
): ?string {
    if (!is_string($value)) return null;
    return preg_match($pattern, $value) === 1 ? $value : null;
}

/**
 * Validate a redirect URL against a hardcoded allowlist of safe paths.
 *
 * WHY AN ALLOWLIST:
 *   FILTER_VALIDATE_URL accepts javascript:alert(1) as structurally valid!
 *   Open redirect (CWE-601) allows phishing via your own trusted domain.
 *   The only fully safe approach: enumerate the exact paths you allow.
 *
 * @param mixed    $value         Raw input (e.g. $_GET['next'])
 * @param string[] $allowed_paths Hardcoded list of safe relative paths
 * @return string|null            A safe relative path or null
 */
function validate_redirect_url(
    mixed $value,
    array $allowed_paths = ['/dashboard', '/profile', '/orders', '/settings']
): ?string {
    if (!is_string($value)) return null;

    // Extract path component only — drop scheme, host, query, fragment
    $path = parse_url($value, PHP_URL_PATH);
    if ($path === null || $path === false || $path === '') return null;

    // Normalize leading slash
    $path = '/' . ltrim($path, '/');

    return in_array($path, $allowed_paths, true) ? $path : null;
}

/**
 * Sanitize free-form text for storage.
 * NOTE: This does NOT make text safe for HTML output.
 *       Always use htmlspecialchars() at the template/output layer.
 *       This function removes the most dangerous invisible characters.
 *
 * @param mixed $value      Raw input
 * @param int   $max_length Maximum allowed character count (UTF-8 aware)
 * @return string|null      Cleaned string or null if empty/invalid
 */
function sanitize_text_input(mixed $value, int $max_length = 255): ?string
{
    if (!is_string($value)) return null;

    // Trim whitespace and limit length (UTF-8 aware)
    $value = mb_substr(trim($value), 0, $max_length, 'UTF-8');

    // Remove null bytes (\x00) — used to bypass regex and truncate C strings
    // Remove non-printable ASCII control chars except \t \n \r
    $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value);

    return ($value === null || $value === '') ? null : $value;
}

/**
 * Validate a URL that must use https: scheme.
 * Combines filter_var structural validation with explicit scheme check.
 *
 * @param mixed $value  Raw input
 * @return string|null  Validated https URL or null
 */
function validate_https_url(mixed $value): ?string
{
    if (!is_string($value)) return null;

    // First: structural URL validation
    $url = filter_var(trim($value), FILTER_VALIDATE_URL);
    if ($url === false) return null;

    // Second: scheme must be https — filter_var alone allows javascript:
    $scheme = parse_url($url, PHP_URL_SCHEME);
    return ($scheme === 'https') ? $url : null;
}

// ============================================================
// USAGE — fail-closed: null → reject with HTTP 400
// ============================================================

$age      = validate_int($_POST['age'] ?? null, 0, 150);
$email    = validate_email($_POST['email'] ?? null);
$username = validate_slug($_POST['username'] ?? null, '/^[a-zA-Z0-9_]{3,32}$/');
$redirect = validate_redirect_url($_GET['next'] ?? null);
$comment  = sanitize_text_input($_POST['comment'] ?? null, 500);

// Reject immediately on invalid type — never reach business logic with bad data
if ($age === null) {
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid age value.']));
}

if ($email === null) {
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid email address.']));
}

// At this point:
// $age      is guaranteed int between 0 and 150
// $email    is guaranteed lowercase RFC-valid email string
// $username is guaranteed alphanumeric slug or null (optional field)
// $redirect is guaranteed one of the allowed paths or null (show default)
// $comment  is guaranteed null-byte-free string or null (optional field)

echo "Validation passed!\n";
