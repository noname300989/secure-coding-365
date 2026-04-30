# Day 14: Functions & Input Sanitization

**Phase:** Programming Foundations & Setup  
**Module:** PHP Foundations  
**Language:** PHP  
**Topics:** User-defined functions, `filter_var()`, input sanitization patterns, whitelist vs blacklist validation

---

## What You'll Learn

- How PHP functions become security boundaries — and when they fail to be
- The difference between **validation** (is this value acceptable?) and **sanitization** (make this value safe)
- `filter_var()` and `filter_input()` — the right tool for the right context
- **Whitelist vs blacklist** validation philosophy and why whitelists always win
- Building reusable, testable sanitization functions that centralize trust decisions
- CWE-20 (Improper Input Validation), CWE-116 (Improper Encoding), CWE-184 (Incomplete Denylist)

---

## Real-World Context

In 2021, a popular PHP-based e-commerce platform exposed millions of users because a developer wrote a custom `cleanInput()` function that stripped `<script>` tags. The attacker submitted `<scr<script>ipt>alert(1)</scr</script>ipt>` — the naive blacklist removed the inner `<script>` fragment, and the outer shell reconstituted a perfect XSS payload.

This is the fundamental lesson of Day 14: **Functions are trust checkpoints.** A well-designed input-handling function should:
1. Define exactly *what is allowed* (whitelist mindset)
2. Reject everything that doesn't match — don't try to fix bad input
3. Return a typed value, not a raw string
4. Be testable in isolation

---

## Vulnerable Code

See [`code/vulnerable_input.php`](code/vulnerable_input.php)

**CWEs Demonstrated:**
- CWE-184: Incomplete List of Disallowed Inputs (blacklist bypass)
- CWE-20: Improper Input Validation (no type enforcement)
- CWE-601: URL Redirection to Untrusted Site (open redirect)

**Key vulnerabilities:**
- `str_replace('<script>', '', $input)` is bypassed by `<SCRIPT>`, `<scr<script>ipt>`, `<img onerror=...>`
- SQL keyword stripping via `str_replace` breaks legitimate data (e.g., "DROPDOWN") and misses `SeLeCt`
- No type enforcement — `$age` is still a string after "cleaning"
- Function gives false confidence — developers think it's safe

---

## Secure Code

See [`code/secure_input.php`](code/secure_input.php)

**Security Improvements:**
- Each function validates ONE type and returns typed data or `null` (never a modified string)
- `filter_var(FILTER_VALIDATE_INT)` is implemented in C and handles all edge cases
- `validate_redirect_url()` uses a hardcoded allowlist of safe paths — attacker-controlled hosts are structurally impossible
- Null byte and control character stripping in `sanitize_text_input()`
- All functions are small, single-purpose, and unit-testable

**Critical gotcha documented:** `filter_var()` returns `false` on failure, not `null`. Always check `=== false`.

---

## Key Takeaways

1. **Validate, don't sanitize.** Validation rejects unacceptable input. Sanitization modifies it — but modification can fail. Prefer rejection over transformation for logic inputs.
2. **Whitelists beat blacklists — always.** A blacklist promises you've thought of everything. You haven't. A whitelist says "only these exact values are allowed."
3. **Return typed values, not cleaned strings.** `validate_int()` should return `int|null`, not a sanitized string. Types enforce constraints at the language level.
4. **`filter_var()` returns `false`, not `null`.** Check `=== false` strictly. A value of `0` is falsy but valid in many contexts.
5. **`FILTER_VALIDATE_URL` allows `javascript:` schemes.** Always extract and check the scheme separately after validation.

---

## Mini Challenge

See [`code/SearchController_challenge.php`](code/SearchController_challenge.php)

Write a `validate_search_params(array $input): array|false` function that validates:
- `q`: string, 2–100 chars, alphanumeric + spaces + hyphens only
- `category_id`: int, 1–500 (optional, default null)
- `sort`: one of `price_asc`, `price_desc`, `newest`, `rating`
- `page`: int, 1–999 (optional, default 1)

---

## Quick Quiz

**Q1.** What does `filter_var("0", FILTER_VALIDATE_INT)` return?  
a) `null`  
b) `false`  
c) `0` (integer) ✅  
d) `"0"` (string)  

**Q2.** A developer uses `FILTER_VALIDATE_URL` to validate a redirect URL. What attack is still possible?  
a) SQL Injection  
b) Open Redirect via `javascript:alert(1)` URL ✅  
c) Path Traversal  
d) Remote File Inclusion  

**Q3.** Which of these is a *whitelist* validation approach?  
a) `str_replace(['<script>', 'DROP TABLE'], '', $input)` — blacklist  
b) `if (strpos($input, "'") !== false) die('invalid');` — blacklist  
c) `if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $input)) return null;` ✅ — whitelist  
d) `htmlspecialchars($input, ENT_QUOTES)` — output encoding, not validation  

---

## References

- [PHP Filter Functions Manual](https://www.php.net/manual/en/book.filter.php)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
