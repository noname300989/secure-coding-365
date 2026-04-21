# Day 5: Methods & Input Validation

**Phase:** Programming Foundations & Setup  
**Module:** Java Foundations  
**Language:** Java  
**CWEs Covered:** CWE-20, CWE-252, CWE-129, CWE-476, CWE-117  

---

## Overview

Methods are your application's public contract with the world. Every parameter that enters a method is untrusted data until proven otherwise. This lesson covers the critical practice of validating inputs at the method boundary — the most effective defense against a wide class of attacks.

CWE-20 (Improper Input Validation) consistently appears in the OWASP Top 10 and CWE Top 25. Heartbleed (CVE-2014-0160) and the Poly Network $611M DeFi hack both trace to missing or inadequate method-level validation.

---

## Concepts Covered

- **Method entry-point validation** — validate all parameters before any logic runs
- **Allowlist vs. blocklist validation** — why allowlisting is always more secure
- **Numeric bounds checking** — positive-only, range constraints for business logic
- **Return value checking (CWE-252)** — never ignore the result of mutating operations
- **Log injection prevention (CWE-117)** — allowlist validation strips newlines from log inputs
- **Centralized validation utilities** — one class, audited once, used everywhere

---

## Files

| File | Description |
|------|-------------|
| `InputValidator.java` | Reusable centralized validation utility |
| `VulnerableUserService.java` | ❌ Service with 4 classic input validation flaws |
| `SecureUserService.java` | ✅ Secure version using InputValidator |
| `BankAccountChallenge.java` | 🏋️ Mini challenge skeleton |

---

## Key Takeaways

1. **Validate at the method entry point, every time.** Never assume the caller validated input. Each layer validates independently.
2. **Use allowlists, not blocklists.** `^[a-zA-Z0-9_-]+$` is safer than blocking specific bad characters.
3. **Positive integers must have explicit bounds.** A negative `amount` in a financial transfer is a business logic attack.
4. **Never ignore return values.** `list.remove()`, `map.put()`, file operations — all return status you must check.
5. **Centralize validation.** One `InputValidator` class is easier to audit and fix than 50 scattered null checks.

---

## References

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-252: Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CVE-2014-0160: Heartbleed](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)
