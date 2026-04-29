<?php
/**
 * Day 13: Mini Challenge — Secure Search Controller
 *
 * YOUR TASK: Complete the TODO sections below to build a
 * production-safe search endpoint using PHP superglobals securely.
 *
 * Requirements:
 * 1. Read 'q' from GET — string, max 100 chars
 * 2. Read 'page' from GET — integer, 1–1000, default 1
 * 3. Start a secure session (cookie-only, httponly, SameSite=Strict)
 * 4. Require authenticated session — redirect to /login if not set
 * 5. Output results with proper XSS encoding
 * 6. BONUS: Use filter_input_array() to read both params at once
 *
 * Test your solution with:
 * ?q=<script>alert(1)</script>&page=-5
 * Expected: XSS not executed, page defaults to 1
 */

declare(strict_types=1);

// TODO 1: Configure and start a secure PHP session
// Hints:
//   ini_set('session.use_only_cookies', '1');
//   ini_set('session.cookie_httponly', '1');
//   ini_set('session.cookie_samesite', 'Strict');
//   session_start();


// TODO 2: Check for authenticated session
// If $_SESSION['user_id'] is not set, redirect to /login
// if (empty($_SESSION['user_id'])) { ... }


// TODO 3: Read and validate inputs
// Use filter_input() or filter_input_array()
// $search = ?
// $page   = ?  (default to 1 if invalid/missing)


// TODO 4: Simulate search results (in a real app, query the DB here)
$mockResults = [
    "Article about {$search} — page {$page}",
    "Another result for {$search}",
    "Third result matching your query",
];


// TODO 5: Output results with XSS-safe encoding
// Use htmlspecialchars($val, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Search Results</title>
</head>
<body>
<!-- TODO: Render $search and $page safely -->
<h1>Results for: <!-- ENCODE HERE --></h1>
<p>Page: <!-- ENCODE HERE --></p>
<ul>
    <?php foreach ($mockResults as $result): ?>
        <li><?php /* TODO: encode $result */ echo $result; ?></li>
    <?php endforeach; ?>
</ul>
</body>
</html>
