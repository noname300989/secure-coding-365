<?php
// VulnerableAuthService.php
// ⚠️ VULNERABLE CODE — DO NOT USE IN PRODUCTION
// Demonstrates PHP type juggling vulnerabilities
// CWE-1289: Improper Validation of Unsafe Equivalence in Input

class VulnerableAuthService {

    // Simulated DB hash for user 'admin'
    // This is md5('240610708') — a "magic hash" starting with 0e
    private string $storedHash = 'md5:0e462097431906509019562988736854';

    /**
     * ⚠️ VULNERABLE: Uses loose == comparison on hashes
     *
     * Attack: md5('QNKCDZO') = '0e830400451993494058024219903391'
     * Both hashes start with '0e' followed by digits.
     * PHP evaluates them as scientific notation: 0×10^N = 0
     * So '0e462097...' == '0e830400...' evaluates to TRUE!
     *
     * An attacker just needs any string whose MD5 starts with '0e'.
     */
    public function login(string $username, string $inputPassword): bool {
        $inputHash = 'md5:' . md5($inputPassword);

        // ⚠️ DANGEROUS: == does type coercion!
        if ($username == 'admin' && $inputHash == $this->storedHash) {
            return true;
        }
        return false;
    }

    /**
     * ⚠️ VULNERABLE: JSON API endpoint — type juggling on user_id
     *
     * Attack: Send {"user_id": true} in JSON body.
     * PHP: true == 1 evaluates to TRUE.
     * This returns the admin account (id=1) to any caller!
     */
    public function getUser(mixed $userId): array {
        $users = [
            1 => ['name' => 'Alice', 'role' => 'admin'],
            2 => ['name' => 'Bob',   'role' => 'user'],
        ];

        foreach ($users as $id => $user) {
            if ($id == $userId) {    // ⚠️ loose == : true == 1 is TRUE
                return $user;
            }
        }
        return [];
    }

    /**
     * ⚠️ VULNERABLE: strcmp() array bypass (PHP < 5.5 classic)
     *
     * Attack: Submit password as array: ?password[]=anything
     * strcmp(array, string) returns NULL (not an integer).
     * NULL == 0 is TRUE in PHP (loose comparison).
     * Authentication bypassed!
     */
    public function legacyLogin(string $user, mixed $password): bool {
        $realPassword = 'hunter2';
        // ⚠️ If $password is an array, strcmp returns null
        // null == 0 → TRUE → login bypassed
        if (strcmp($password, $realPassword) == 0) {
            return true;
        }
        return false;
    }

    /**
     * ⚠️ VULNERABLE: PHP 7 zero-looseness
     *
     * In PHP 7: 0 == "foobar" evaluates to TRUE
     * Because "foobar" converts to int 0, and 0 == 0.
     * An attacker submitting a non-numeric token could match
     * a database entry with token=0.
     */
    public function validateApiKey(mixed $submittedKey): bool {
        $storedKey = 0; // e.g., uninitialized/null key in old DB row

        // ⚠️ In PHP 7: "any_string" == 0 is TRUE!
        if ($submittedKey == $storedKey) {
            return true; // ← any non-numeric string bypasses this!
        }
        return false;
    }
}

// ============================================================
// Demonstration of dangerous comparisons
// ============================================================
echo "=== PHP Type Juggling Dangers ===\n\n";

// Magic hash comparison
$hash1 = '0e462097431906509019562988736854'; // md5('240610708')
$hash2 = '0e830400451993494058024219903391'; // md5('QNKCDZO')
echo "Magic hash attack:\n";
echo "  '$hash1' == '$hash2' → " . var_export($hash1 == $hash2, true) . "\n";   // TRUE ⚠️
echo "  '$hash1' === '$hash2' → " . var_export($hash1 === $hash2, true) . "\n"; // FALSE ✅

// Type coercion table
echo "\nType coercion table:\n";
echo "  '0' == false  → " . var_export('0' == false, true) . "\n";   // true ⚠️
echo "  '' == false   → " . var_export('' == false, true) . "\n";    // true ⚠️
echo "  '01' == '1'   → " . var_export('01' == '1', true) . "\n";   // true ⚠️
echo "  '1e2' == '100'→ " . var_export('1e2' == '100', true) . "\n"; // true ⚠️
