<?php
// StrictTypesDemo.php
// ✅ PHP 8+ strict type declarations — your best defense against type juggling
// Run: php StrictTypesDemo.php

declare(strict_types=1);

// ============================================================
// 1. Basic strict_types enforcement
// ============================================================

function processAge(int $age): string {
    if ($age < 0 || $age > 150) {
        throw new \InvalidArgumentException("Age must be between 0 and 150, got: {$age}");
    }
    return "Age: {$age}";
}

// Without strict_types: processAge("25") → silently converts to 25
// With strict_types:    processAge("25") → TypeError thrown ✅
echo processAge(25) . "\n"; // ✅ Works

// Uncomment to see TypeError:
// echo processAge("25") . "\n"; // ← TypeError: Argument 1 must be int, string given

// ============================================================
// 2. Union types for controlled flexibility (PHP 8.0+)
// ============================================================

function parseId(int|string $id): int {
    if (is_string($id)) {
        // ✅ Only allow purely numeric strings (no "+1", "0x10", "1.5")
        if (!ctype_digit($id)) {
            throw new \InvalidArgumentException("Invalid ID format: '{$id}'");
        }
        return (int) $id;
    }
    if ($id <= 0) {
        throw new \InvalidArgumentException("ID must be positive");
    }
    return $id;
}

echo parseId(42) . "\n";     // ✅ 42
echo parseId("42") . "\n";   // ✅ 42 (valid numeric string)
// parseId("42abc");          // ← InvalidArgumentException ✅
// parseId(true);             // ← TypeError (bool not in int|string) ✅

// ============================================================
// 3. PHP 8.1+ Enums — prevent magic string comparisons
// ============================================================

enum UserRole: string {
    case Admin  = 'admin';
    case Editor = 'editor';
    case Viewer = 'viewer';
}

function checkAccess(UserRole $role): bool {
    // ✅ Can't pass 'ADMIN' or 0 or true — must be a UserRole enum value
    return $role === UserRole::Admin;
}

echo checkAccess(UserRole::Admin)  ? "Admin: access granted ✅\n" : "Admin: denied\n";
echo checkAccess(UserRole::Viewer) ? "Viewer: access granted\n" : "Viewer: denied ✅\n";

// checkAccess('admin');  // ← TypeError: must be UserRole ✅
// checkAccess(1);        // ← TypeError ✅

// ============================================================
// 4. Strict === vs loose == comparison table
// ============================================================

echo "\n=== Comparison Safety Demo ===\n";

$values = [
    ['0', false],
    ['', false],
    ['0e123', '0e456'],
    ['01', '1'],
    [0, 'foo'],  // PHP 7 only (PHP 8 fixed this)
    [100, '1e2'],
];

foreach ($values as [$a, $b]) {
    $aStr = var_export($a, true);
    $bStr = var_export($b, true);
    $loose  = ($a == $b)  ? 'TRUE  ⚠️' : 'false ✅';
    $strict = ($a === $b) ? 'TRUE  ❌' : 'false ✅';
    echo sprintf("  %-20s == %-20s → loose: %s | strict: %s\n",
        $aStr, $bStr, $loose, $strict);
}

// ============================================================
// 5. Type-safe input parsing from JSON
// ============================================================

function parseUserInput(string $jsonBody): array {
    $data = json_decode($jsonBody, true);

    if (!is_array($data)) {
        throw new \InvalidArgumentException('Invalid JSON');
    }

    // ✅ Validate each field with explicit type checks
    $userId = $data['user_id'] ?? null;
    if (!is_int($userId) || $userId <= 0) {
        throw new \InvalidArgumentException('user_id must be a positive integer');
    }

    $action = $data['action'] ?? null;
    if (!is_string($action) || !in_array($action, ['read', 'write', 'delete'], true)) {
        throw new \InvalidArgumentException("Invalid action: " . var_export($action, true));
    }

    return ['user_id' => $userId, 'action' => $action];
}

// ✅ Valid input
$safe = parseUserInput('{"user_id": 5, "action": "read"}');
echo "\nParsed: user_id={$safe['user_id']}, action={$safe['action']} ✅\n";

// ✅ Rejects type-confused input
try {
    parseUserInput('{"user_id": true, "action": "read"}');
} catch (\InvalidArgumentException $e) {
    echo "Rejected type confusion: " . $e->getMessage() . " ✅\n";
}
