<?php
/**
 * VULNERABLE: Blacklist-based "sanitization"
 * 
 * CWE-184: Incomplete List of Disallowed Inputs
 * CWE-20:  Improper Input Validation
 * CWE-601: URL Redirection to Untrusted Site
 * 
 * This approach LOOKS safe but is trivially bypassed.
 */

function cleanInput(string $input): string
{
    // Try to strip dangerous HTML tags
    $input = str_replace('<script>', '', $input);
    $input = str_replace('</script>', '', $input);
    $input = str_replace('javascript:', '', $input);
    $input = str_replace('onerror=', '', $input);
    $input = str_replace('onload=', '', $input);

    // Remove SQL keywords (naive attempt)
    $input = str_replace('SELECT', '', $input);
    $input = str_replace('DROP', '', $input);
    $input = str_replace('INSERT', '', $input);
    $input = str_replace('DELETE', '', $input);

    return $input;
}

// Usage — FALSE CONFIDENCE
$username = cleanInput($_POST['username'] ?? '');
$age      = cleanInput($_POST['age'] ?? '');       // Still a string!
$redirect = cleanInput($_GET['next'] ?? '');       // Open redirect risk

// ============================================================
// BYPASSES that work against this function:
// ============================================================

// 1. Case mismatch bypass
//    Input:  <ScRiPt>alert(document.cookie)</ScRiPt>
//    Output: <ScRiPt>alert(document.cookie)</ScRiPt>  ← untouched!

// 2. Nested injection (Samy Worm technique)
//    Input:  <scr<script>ipt>alert(1)</scr</script>ipt>
//    str_replace removes inner <script> and </script>
//    Output: <script>alert(1)</script>  ← reconstituted!

// 3. Mixed-case attribute bypass
//    Input:  <img src=x oNeRrOr=alert(1)>
//    Output: <img src=x oNeRrOr=alert(1)>  ← untouched!

// 4. HTML entity encoding bypass
//    Input:  &#106;avascript:alert(1)
//    Output: &#106;avascript:alert(1)  ← browser decodes to javascript:!

// 5. SQL keyword case bypass
//    Input:  SeLeCt * FrOm users--
//    Output: SeLeCt * FrOm users--  ← untouched!

// 6. $age is STILL a STRING — no type enforcement
//    validate_int($_POST['age']) ← this never happens
//    An attacker can pass age="-1" or age="abc" and reach business logic

// 7. $redirect open redirect
//    Input:  ?next=https://evil.com/phishing
//    cleanInput sees no "dangerous" content → passes through
//    header("Location: $redirect") → ships user to attacker site

// LESSON: Blacklists cannot enumerate every way to say something dangerous.
//         False confidence from "sanitization" is MORE dangerous than no sanitization,
//         because it removes developer vigilance.
