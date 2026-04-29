# Day 13: Arrays & Superglobals Security (PHP)

**Phase:** Programming Foundations & Setup  
**Module:** PHP Foundations  
**Language:** PHP  
**CWEs Covered:** CWE-79, CWE-89, CWE-235, CWE-290, CWE-384, CWE-601, CWE-1004

---

## What You'll Learn

- Why PHP superglobals (`$_GET`, `$_POST`, `$_COOKIE`, `$_SESSION`, `$_SERVER`) are dangerous by default
- How attackers exploit raw superglobal access for SQL injection, XSS, session fixation, and IP spoofing
- How to safely read and validate superglobal data with `filter_input()`
- Session fixation (CWE-384) and how `session_regenerate_id(true)` prevents it
- Cookie security flags: `HttpOnly`, `Secure`, `SameSite`
- The `$_SERVER` trap — which entries are attacker-controlled

---

## Real-World Context

PHP's superglobals are the #1 source of PHP vulnerabilities:

- **phpBB SQL injections (pre-2009):** Direct `$_GET`/`$_POST` params concatenated into SQL queries — entire forum databases exposed
- **WordPress plugin CVEs (perennial):** Hundreds of CVEs annually from `$_REQUEST['action']` without sanitization
- **Session fixation in osCommerce (CWE-384):** Attackers set their own `PHPSESSID` via `$_GET`, hijacking authenticated sessions after victim logs in
- **IP allowlist bypass (CWE-290):** Trusting `$_SERVER['HTTP_CLIENT_IP']` which any attacker can spoof via request headers

---

## The Problem

PHP makes accessing user-controlled data dangerously easy:

```php
$userId = $_GET['user_id'];   // raw, untyped, unvalidated
$search = $_GET['q'];          // reflected XSS entry point
$role   = $_COOKIE['role'];    // trivially forged in browser
```

Every superglobal value is **attacker-controlled**. Writing `$_POST['email']` and treating it as clean data is the mistake that powers thousands of CVEs per year.

---

## Key Takeaways

- **Every superglobal is attacker-controlled data** — `$_GET`, `$_POST`, `$_COOKIE`, and HTTP-derived `$_SERVER` entries can be freely crafted by a hostile client
- **Use `filter_input()` instead of direct array access** — forces you to declare expected type/format; invalid input returns `null`/`false` instead of a dangerous string
- **Always `session_regenerate_id(true)` after login** — eliminates session fixation; do it unconditionally every time privilege changes
- **Security roles live in `$_SESSION`, never in cookies** — cookies are client-side and trivially editable; `$_SESSION` is server-side
- **`$_SERVER` is not pure "server" data** — `HTTP_*` entries come from request headers; only trust `REMOTE_ADDR` without explicit proxy allowlisting

---

## Files

| File | Description |
|------|-------------|
| `vulnerable_superglobals.php` | Shows dangerous raw superglobal patterns |
| `secure_superglobals.php` | `filter_input()`, secure sessions, safe cookies |
| `SecureSession.php` | Reusable session management class |
| `SearchController_challenge.php` | Mini challenge starter file |

---

## Mini Challenge

Build a secure PHP search form with:

1. HTML form (GET method) with `q` text field and `page` number field
2. PHP handler that:
   - Reads `q` with `filter_input()` — string, max 100 chars
   - Reads `page` with `filter_input()` — integer, 1–1000, defaults to 1
   - Starts a secure session (cookie-only, httponly, SameSite=Strict)
   - Checks `$_SESSION['user_id']` — if not set, redirects to `/login`
   - Outputs results with proper XSS encoding
3. **Bonus:** Use `filter_input_array()` to read both params in one shot

---

## Quick Quiz Answers

1. **b** — Session fixation; `session_regenerate_id(true)` after login
2. **b** — Improper Access Control via spoofable header (CWE-290)
3. **c** — `filter_input()` with `min_range`/`max_range` options

---

## References

- [PHP: filter_input()](https://php.net/filter_input)
- [OWASP: Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-290: Authentication Bypass via Spoofed Header](https://cwe.mitre.org/data/definitions/290.html)
- [PHP: setcookie() options array](https://php.net/setcookie)
