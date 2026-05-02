<?php
// File: vulnerable_error_handling.php
// ⚠️ DO NOT USE IN PRODUCTION — This demonstrates insecure error handling

ini_set('display_errors', 1);          // ☠️ CWE-209: exposes full stack trace in browser
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// No custom exception handler — PHP default shows full trace including file paths,
// framework version, and potentially DSN with password

// Fake DB connect — if this throws, DSN including password leaks to browser
function getUser(int $id): array {
    $pdo = new PDO('mysql:host=db;dbname=app', 'root', 'S3cr3t!Pass');
    // ☠️ If this throws a PDOException, the error message includes the DSN!
    $stmt = $pdo->query("SELECT * FROM users WHERE id = $id");
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// ☠️ Logging passwords and tokens directly (CWE-532)
function processPayment(string $cardNumber, float $amount): void {
    // Full PAN written to plain /var/log/php_errors.log
    error_log("Processing payment: card=$cardNumber amount=$amount");

    try {
        // ... payment logic ...
        throw new RuntimeException("Gateway timeout: details for card $cardNumber");
    } catch (Exception $e) {
        // ☠️ CWE-209: Stack trace + card number echoed to user
        echo "Payment failed: " . $e->getMessage();
    }
}

// ☠️ Log injection via unsanitized user input (CWE-117)
function loginAttempt(string $username): void {
    // If $username = "admin\nINFO: Login success for: root"
    // attacker injects a fake successful login entry into the log!
    error_log("Login attempt for: $username");
}

// ☠️ Unhandled exception — full trace displayed in browser
function riskyOperation(): void {
    throw new RuntimeException("Database query failed: SELECT * FROM internal_table WHERE ...");
}

riskyOperation(); // Unhandled — PHP renders full stack trace to browser
