<?php
// File: ChallengeResetPassword.php
// 🏋️ MINI CHALLENGE — Day 16
//
// The VULNERABLE version below has at least 5 security issues.
// Your task: rewrite it securely using Monolog.
//
// HINT: Issues include display_errors, hardcoded DSN, logging plaintext password,
//       echoing new password to user, no input validation, and no password hashing.

// ============================================================
// ⚠️ VULNERABLE VERSION (DO NOT USE)
// ============================================================

/*
ini_set('display_errors', 1);

function resetPassword(string $email, string $newPass): void {
    $pdo = new PDO('mysql:host=localhost;dbname=shop', 'root', 'admin123');
    $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE email = ?");
    $stmt->execute([$newPass, $email]);
    error_log("Password reset for $email to: $newPass at " . date('Y-m-d'));
    echo "Password updated to: $newPass";
}
resetPassword($_GET['email'], $_GET['pass']);
*/

// ============================================================
// ✅ YOUR SECURE SOLUTION GOES HERE
// ============================================================

// Security issues to fix:
// 1. display_errors = 1 → must be Off in production
// 2. Hardcoded DSN with root password in function body
// 3. Logging the plaintext new password (CWE-532)
// 4. Echoing the new password back to the user (CWE-209)
// 5. No input validation on $email or $newPass
// 6. Password stored in plaintext (use password_hash() with PASSWORD_ARGON2ID)
// 7. No CSRF protection on this password reset endpoint
// 8. $email taken directly from $_GET — should be POST + validated

// Your rewrite:
// use Monolog\Logger;

// function resetPassword(string $email, string $newPass, Logger $logger, PDO $pdo): void {
//     // TODO: validate $email
//     // TODO: hash $newPass with password_hash($newPass, PASSWORD_ARGON2ID)
//     // TODO: update DB with hashed password
//     // TODO: log sanitized event (email, timestamp) — NOT the password
//     // TODO: return generic success message only
// }

// Bonus: what does password_hash(PASSWORD_ARGON2ID) give you vs PASSWORD_DEFAULT?
