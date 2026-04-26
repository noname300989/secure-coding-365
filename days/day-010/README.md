# Day 10: Variables, Types & Type Juggling Dangers

**Phase:** Programming Foundations & Setup
**Module:** PHP Foundations
**Language:** PHP
**Date:** 2026-04-26

---

## Overview

PHP's loose typing system is one of the most exploited quirks in web security. PHP's `==` operator performs type coercion before comparing, which means values of completely different types can be considered "equal" — opening the door to authentication bypass, privilege escalation, and logic flaws.

Key vulnerabilities covered:
- **Magic Hash attacks** — hashes starting with `0e` evaluated as scientific notation
- **JSON type confusion** — `true == 1` returning admin data
- **strcmp() array bypass** — passing arrays to strcmp() returns null (PHP < 5.5)
- **CWE-1289**: Improper Validation of Unsafe Equivalence in Input

---

## Key Concepts

### PHP Type Juggling Comparison Table

| Expression          | `==` Result | `===` Result |
|---------------------|-------------|--------------|
| `"0" == false`      | `true`  ❌  | `false` ✅   |
| `"" == false`       | `true`  ❌  | `false` ✅   |
| `"1" == true`       | `true`  ❌  | `true`  ✅   |
| `"01" == "1"`       | `true`  ❌  | `false` ✅   |
| `"0e123" == "0e456"`| `true`  ❌  | `false` ✅   |
| `100 == "1e2"`      | `true`  ❌  | `false` ✅   |
| `0 == "foo"` (PHP7) | `true`  ❌  | `false` ✅   |
| `0 == "foo"` (PHP8) | `false` ✅  | `false` ✅   |

### Magic Hash Phenomenon

PHP's `==` converts strings that look like scientific notation to floats:
- `"0e462097431906509019562988736854"` → float `0.0`
- `"0e123"` → float `0.0`
- Therefore `"0e462097431906509019562988736854" == "0e123"` → `true`

Known magic strings (MD5 producing `0e...` hashes):
- `240610708` → `0e462097431906509019562988736854`
- `QNKCDZO` → `0e830400451993494058024219903391`
- `aabg74342` → `0e410612711802554980596735710338`

---

## Files

| File | Description |
|------|-------------|
| `code/VulnerableAuthService.php` | Demonstrates loose comparison, magic hash, and strcmp bypass |
| `code/SecureAuthService.php` | Uses password_hash/verify, ===, hash_equals, strict_types |
| `code/StrictTypesDemo.php` | PHP 8+ strict_types, enum types, union types |
| `code/ChallengePasswordReset.php` | Mini challenge — find and fix 4+ security issues |

---

## Secure Coding Rules

1. ✅ Always use `===` (strict equality) — never `==` for security comparisons
2. ✅ Add `declare(strict_types=1)` to every PHP file
3. ✅ Use `password_hash()` + `password_verify()` — never MD5/SHA1 for passwords
4. ✅ Use `hash_equals()` for token/HMAC comparisons (constant-time)
5. ✅ Validate and type-check all external input before processing
6. ✅ Use PHP 8.1+ Enums to prevent magic string comparisons

---

## References

- [CWE-1289: Improper Validation of Unsafe Equivalence](https://cwe.mitre.org/data/definitions/1289.html)
- [PHP Manual: Type Juggling](https://www.php.net/manual/en/language.types.type-juggling.php)
- [Magic Hashes Cheat Sheet (Spaze)](https://github.com/spaze/hashes)
- [OWASP Testing for Type Juggling](https://owasp.org/www-project-web-security-testing-guide/)
