<?php
// htmlspecialchars_vs_htmlentities.php
// Deep-dive comparison of the two main HTML encoding functions in PHP

// =====================================================
// htmlspecialchars() — converts only the 5 dangerous HTML characters:
//   & → &amp;    " → &quot;    ' → &#039;
//   < → &lt;     > → &gt;
// =====================================================

$xssPayload = '<script>alert("XSS")</script>';
$encoded = htmlspecialchars($xssPayload, ENT_QUOTES, 'UTF-8');
echo $encoded;
// Output: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;
// ✅ Safe for HTML context. Preferred for performance.

// =====================================================
// htmlentities() — converts ALL applicable characters to HTML entities
// including accented characters like é → &eacute;, ü → &uuml;, etc.
// =====================================================

$euroSign = "Price: €100";
echo htmlentities($euroSign, ENT_QUOTES, 'UTF-8');      // Price: &euro;100
echo htmlspecialchars($euroSign, ENT_QUOTES, 'UTF-8');  // Price: €100 (unchanged)

// When to use each:
// htmlspecialchars() → 99% of cases. Fast, sufficient for XSS prevention.
// htmlentities()     → When you need ASCII-only output (email clients, legacy systems)
//                      or when charset handling is uncertain.

// =====================================================
// ⚠️ BOTH are useless without ENT_QUOTES in single-quote attributes!
// =====================================================

$name = "O'Brien";

// ❌ WRONG — without ENT_QUOTES, single quotes aren't encoded
echo "<input value='" . htmlspecialchars($name) . "'>";
// Output: <input value='O'Brien'> ← BREAKS the attribute, attribute injection!

// ✅ CORRECT — ENT_QUOTES encodes single AND double quotes
echo "<input value='" . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "'>";
// Output: <input value='O&#039;Brien'> ← Safe!

// =====================================================
// ENT_SUBSTITUTE flag — prevents charset confusion attacks
// =====================================================

// Without ENT_SUBSTITUTE, invalid UTF-8 sequences return an empty string
// which could allow attackers to bypass encoding with crafted multibyte chars
// ENT_SUBSTITUTE replaces invalid sequences with a Unicode replacement character

$malformedUtf8 = "\x80\x81\x82"; // invalid UTF-8 bytes

// ❌ Without ENT_SUBSTITUTE
$result1 = htmlspecialchars($malformedUtf8, ENT_QUOTES, 'UTF-8');
var_dump($result1); // string(0) "" — empty! Encoding silently failed

// ✅ With ENT_SUBSTITUTE
$result2 = htmlspecialchars($malformedUtf8, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
var_dump($result2); // string(3) "???" — replacement chars shown instead

// =====================================================
// The recommended wrapper function
// =====================================================

function e(string $value): string {
    // ENT_QUOTES: encode single + double quotes
    // ENT_SUBSTITUTE: handle malformed UTF-8 safely
    // 'UTF-8': explicitly set charset (never rely on default)
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Usage:
$userInput = "<script>alert(1)</script> & O'Reilly";
echo e($userInput);
// Output: &lt;script&gt;alert(1)&lt;/script&gt; &amp; O&#039;Reilly
// ✅ Safe to embed in HTML body or HTML attributes
