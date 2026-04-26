<?php
// ChallengePasswordReset.php
// 🏋️ MINI CHALLENGE — Day 10
//
// TASK: Identify ALL security issues in the vulnerable snippet below
// and rewrite it securely. There are at least 4 issues.
//
// VULNERABLE SNIPPET (for analysis only):
// ─────────────────────────────────────────
//
// $data = json_decode(file_get_contents('php://input'), true);
// $token = $data['token'];
// $newPassword = $data['new_password'];
//
// $storedToken = getTokenFromDb($_SESSION['user_id']);
//
// if ($token == $storedToken && strlen($newPassword) > 7) {
//     updatePassword($_SESSION['user_id'], md5($newPassword));
//     echo json_encode(['success' => true]);
// }
//
// ─────────────────────────────────────────
// ISSUES TO FIND:
// 1. Token comparison — what operator is used? What's wrong?
// 2. Password hashing — what function is used? Why is it wrong?
// 3. Input validation — what's missing about $token and $newPassword?
// 4. Session/auth — what security concern is unaddressed?
// BONUS: What HTTP security headers should this endpoint return?
//
// Write your secure version below. Reference answer follows.
// ─────────────────────────────────────────

declare(strict_types=1);

// ============================================================
// YOUR SECURE IMPLEMENTATION GOES HERE
// ============================================================

// ... write your code ...

// ============================================================
// REFERENCE ANSWER (scroll down)
// ============================================================
//
//
//
//
//
//
//
// ─────────────────────────────────────────
// ISSUES IDENTIFIED:
//
// 1. TOKEN COMPARISON: `$token == $storedToken`
//    - Uses loose == operator → type juggling vulnerability
//    - If both tokens happen to start with '0e', they match without being equal!
//    - Fix: Use hash_equals($storedToken, $token) for constant-time comparison
//
// 2. PASSWORD HASHING: `md5($newPassword)`
//    - MD5 is cryptographically broken for passwords (fast, reversible via rainbow tables)
//    - No salt → identical passwords have identical hashes
//    - Fix: Use password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12])
//
// 3. INPUT VALIDATION:
//    - $token not validated as string → could be array, null, boolean
//    - $newPassword not validated for strength — only length > 7 (8 chars minimum is too short)
//    - No CSRF protection — any site could submit this form
//    - Fix: Type-check inputs, enforce stronger password policy
//
// 4. SESSION/AUTH:
//    - Token should be invalidated after use (one-time use)
//    - Token should have expiry check
//    - No rate limiting on reset attempts
//    - Fix: Delete/expire token after successful reset

// ─────────────────────────────────────────
// SECURE REFERENCE IMPLEMENTATION:
// ─────────────────────────────────────────

function securePasswordReset(): void {
    // ✅ Set security headers
    header('Content-Type: application/json');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Cache-Control: no-store');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        return;
    }

    // ✅ Parse and validate JSON input
    $rawBody = file_get_contents('php://input');
    $data = json_decode($rawBody, true);

    if (!is_array($data)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid request body']);
        return;
    }

    // ✅ Explicit type validation for each field
    $token = $data['token'] ?? null;
    $newPassword = $data['new_password'] ?? null;

    if (!is_string($token) || strlen($token) !== 64 || !ctype_xdigit($token)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid token format']);
        return;
    }

    if (!is_string($newPassword) || strlen($newPassword) < 12) {
        http_response_code(400);
        echo json_encode(['error' => 'Password must be at least 12 characters']);
        return;
    }

    // ✅ Session check — ensure user is in a valid reset flow
    if (empty($_SESSION['user_id']) || empty($_SESSION['reset_initiated'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    $userId = (int) $_SESSION['user_id'];

    // ✅ Retrieve token + expiry from DB
    $tokenRecord = getTokenFromDb($userId); // returns ['token' => ..., 'expires_at' => ...]

    if ($tokenRecord === null) {
        http_response_code(400);
        echo json_encode(['error' => 'No active reset token']);
        return;
    }

    // ✅ Check expiry before comparison
    if (strtotime($tokenRecord['expires_at']) < time()) {
        invalidateToken($userId);
        http_response_code(400);
        echo json_encode(['error' => 'Token expired']);
        return;
    }

    // ✅ hash_equals() for constant-time token comparison
    if (!hash_equals($tokenRecord['token'], $token)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid token']);
        return;
    }

    // ✅ password_hash() with bcrypt — never MD5!
    $newHash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
    updatePassword($userId, $newHash);

    // ✅ Invalidate token immediately after use (one-time use)
    invalidateToken($userId);

    // ✅ Regenerate session ID to prevent session fixation
    session_regenerate_id(true);
    unset($_SESSION['reset_initiated']);

    echo json_encode(['success' => true, 'message' => 'Password updated successfully']);
}

// Stub functions (replace with real DB queries using prepared statements)
function getTokenFromDb(int $userId): ?array { return null; }
function updatePassword(int $userId, string $hash): void {}
function invalidateToken(int $userId): void {}
