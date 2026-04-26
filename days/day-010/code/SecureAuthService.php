<?php
// SecureAuthService.php
// ✅ SECURE CODE — Production-ready patterns
// PHP 8.2 — Strict types, proper hashing, safe comparisons

declare(strict_types=1); // ✅ Enforces strict type checking at all call sites

class SecureAuthService {

    /**
     * ✅ SECURE: Uses password_hash() + password_verify()
     *
     * Why this is secure:
     * - password_hash() uses bcrypt (or argon2id) with a random salt
     * - Bcrypt is intentionally slow (configurable cost factor)
     * - password_verify() is constant-time internally
     * - No magic hash vulnerabilities possible (bcrypt output never starts with 0e)
     * - Future-proof: password_needs_rehash() detects when to upgrade
     */
    public function login(string $username, string $inputPassword): bool {
        // Retrieve bcrypt hash from DB (never store plaintext or MD5!)
        $storedHash = $this->getHashFromDb($username);

        if ($storedHash === null) {
            // ✅ Call verify with dummy hash to prevent timing-based
            // username enumeration (response time reveals valid usernames)
            password_verify($inputPassword, '$2y$12$invalidHashXXXXXXXXXXXXXX');
            return false;
        }

        // ✅ password_verify() handles all versions of bcrypt/argon2
        $authenticated = password_verify($inputPassword, $storedHash);

        // ✅ Rehash if cost factor changed or algorithm updated
        if ($authenticated && password_needs_rehash($storedHash, PASSWORD_BCRYPT, ['cost' => 12])) {
            $newHash = password_hash($inputPassword, PASSWORD_BCRYPT, ['cost' => 12]);
            $this->updateHashInDb($username, $newHash);
        }

        return $authenticated;
    }

    /**
     * ✅ SECURE: Strict int type hint + direct array lookup
     *
     * Why secure:
     * - PHP enforces: passing `true` throws TypeError with strict_types=1
     * - Direct $users[$userId] avoids loose comparison loop entirely
     * - ?? [] returns empty array (not null) for missing keys
     */
    public function getUser(int $userId): array { // ✅ int type hint!
        $users = [
            1 => ['name' => 'Alice', 'role' => 'admin'],
            2 => ['name' => 'Bob',   'role' => 'user'],
        ];

        // ✅ Direct array access — no comparison needed
        return $users[$userId] ?? [];
    }

    /**
     * ✅ SECURE: Explicit type validation + hash_equals() for tokens
     *
     * Why secure:
     * - is_string() rejects arrays, booleans, nulls before any comparison
     * - strlen check rejects obviously wrong tokens early
     * - hash_equals() is constant-time: prevents timing attacks (CWE-208)
     */
    public function validateToken(mixed $inputToken): bool {
        // ✅ Validate type first — never trust external input
        if (!is_string($inputToken) || strlen($inputToken) !== 64) {
            return false;
        }

        $realToken = $this->getRealToken();

        // ✅ hash_equals() for constant-time string comparison
        // Unlike ===, it doesn't short-circuit on first mismatch
        return hash_equals($realToken, $inputToken);
    }

    /**
     * ✅ SECURE: API key validation with proper typing
     *
     * - Type hint enforces string input
     * - === strict comparison (no coercion)
     * - hash_equals() for constant-time safety
     */
    public function validateApiKey(string $submittedKey): bool {
        $storedKey = $this->getStoredApiKey();

        if (!is_string($storedKey) || empty($storedKey)) {
            return false; // ✅ Fail closed if stored key is invalid
        }

        // ✅ Constant-time comparison prevents timing attacks
        return hash_equals($storedKey, $submittedKey);
    }

    // ── Private helpers ────────────────────────────────────────────────────

    private function getHashFromDb(string $username): ?string {
        // In real code: prepared statement to DB
        // Return bcrypt hash e.g.: password_hash('secret', PASSWORD_BCRYPT)
        // Return null if user not found
        return null; // placeholder
    }

    private function updateHashInDb(string $username, string $newHash): void {
        // Prepared statement UPDATE: SET password_hash = ? WHERE username = ?
    }

    private function getRealToken(): string {
        // Retrieve from DB/session, not generated fresh each time
        return bin2hex(random_bytes(32)); // placeholder
    }

    private function getStoredApiKey(): string {
        return ''; // placeholder — retrieve from secure config/DB
    }
}

// ============================================================
// How to hash a password (store this in DB at registration)
// ============================================================
$passwordToStore = 'userSuppliedPassword123!';

// ✅ SECURE: Bcrypt with cost 12 (higher = slower = more secure)
$hash = password_hash($passwordToStore, PASSWORD_BCRYPT, ['cost' => 12]);
echo "Bcrypt hash: " . $hash . "\n";
echo "Starts with \$2y\$: " . (str_starts_with($hash, '$2y$') ? 'YES ✅' : 'NO ❌') . "\n";

// ✅ EVEN BETTER: Argon2id (PHP 7.3+, needs --with-password-argon2)
// $hash = password_hash($passwordToStore, PASSWORD_ARGON2ID);

// Verify at login:
$inputAtLogin = 'userSuppliedPassword123!';
echo "Verify match: " . (password_verify($inputAtLogin, $hash) ? 'TRUE ✅' : 'FALSE') . "\n";

$wrongPassword = 'wrongPassword';
echo "Verify wrong: " . (password_verify($wrongPassword, $hash) ? 'TRUE ❌' : 'FALSE ✅') . "\n";
