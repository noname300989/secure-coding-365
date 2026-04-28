<?php
// secure_profile.php
// Context-aware output encoding — the right tool for each context ✅

/**
 * HTML context: encode for HTML body content
 * Converts: & < > " ' into HTML entities
 * ENT_QUOTES encodes both single AND double quotes
 * ENT_SUBSTITUTE replaces malformed UTF-8 (prevents charset attacks)
 */
function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * HTML attribute context: same as e() above — ENT_QUOTES is essential
 * whether you use single or double quote attributes.
 */
function attr(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * URL context: encode values embedded in URLs (query params)
 * urlencode() handles ?, &, =, spaces, etc.
 */
function url_param(string $value): string {
    return urlencode($value);
}

/**
 * JavaScript string context: json_encode gives safe JS string literal.
 * JSON_HEX_TAG    → encodes < and > as \u003C / \u003E
 * JSON_HEX_APOS   → encodes ' as \u0027
 * JSON_HEX_QUOT   → encodes " as \u0022
 * JSON_HEX_AMP    → encodes & as \u0026
 * This prevents </script> injection and ensures the value is safe
 * even inside <script> blocks.
 */
function js(mixed $value): string {
    return json_encode(
        $value,
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE
    );
}

/**
 * URL allowlist validator — prevents javascript: protocol XSS
 */
function safe_redirect_url(string $url, array $allowlist = []): string {
    if (empty($allowlist)) {
        $allowlist = ['/profile', '/dashboard', '/settings'];
    }

    if (in_array($url, $allowlist, true)) {
        return $url;
    }

    // Also accept URLs starting with allowed paths (for sub-paths)
    foreach ($allowlist as $allowed) {
        if (str_starts_with($url, $allowed . '/')) {
            // Validate it's a real relative path (no protocol)
            $scheme = parse_url($url, PHP_URL_SCHEME);
            if ($scheme === null) {
                return $url; // safe relative URL
            }
        }
    }

    return '/profile'; // safe fallback
}

// ——— Reading user input ———
$username   = $_GET['username'] ?? '';
$bio        = $_POST['bio'] ?? '';
$profileUrl = $_GET['redirect'] ?? '/profile';
$comment    = $_POST['comment'] ?? '';

// ✅ Validate redirect URL against allowlist (prevents javascript: protocol)
$safeRedirectUrl = safe_redirect_url($profileUrl);

// ✅ HTML body context
echo "<h1>Welcome, " . e($username) . "!</h1>";

// ✅ HTML body context (stored XSS — encode on OUTPUT, not just on input)
echo "<p class='bio'>" . e($bio) . "</p>";

// ✅ HTML attribute context — using double quotes, but ENT_QUOTES covers both
echo '<a href="' . attr($safeRedirectUrl) . '">View Profile</a>';

// ✅ JavaScript context — json_encode, NOT htmlspecialchars!
echo "<script>var user = " . js($username) . ";</script>";

// ✅ nl2br: ALWAYS encode FIRST, then apply nl2br
echo nl2br(e($comment));  // safe: HTML entities first, then <br> for newlines

// ✅ Content-Security-Policy header for defense in depth
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
