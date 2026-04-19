# Day 3: Control Flow & Secure Logic

**Phase:** Programming Foundations & Setup  
**Module:** Java Foundations  
**Language:** Java  
**CWEs Covered:** CWE-697, CWE-208, CWE-1254  

---

## 🎯 What You'll Learn

Control flow — `if/else`, `switch`, and loops — is the backbone of every program. But poorly structured logic is one of the most common sources of security vulnerabilities:

- **Logic flaws** that allow authentication bypass or privilege escalation  
- **Short-circuit evaluation** — a subtle but dangerous security footgun  
- **Timing attacks** — how an attacker extracts secrets by measuring response latency  
- **Switch-statement fall-through** — silent bugs that cascade into security holes  

---

## 🌍 Real-World Context

### Apple's "goto fail" Bug (CVE-2014-1266)
In 2014, Apple's SSL/TLS implementation had a duplicated `goto fail;` line that caused SSL certificate verification to **always succeed** — meaning ANY certificate, including fraudulent ones, would pass validation. Millions of devices were vulnerable to man-in-the-middle attacks.

```c
// Simplified version of the actual Apple bug:
if ((err = SSLHashSHA1.update(&hashCtx, &serverRandom)) != 0)
    goto fail;
if ((err = SSLHashSHA1.update(&hashCtx, &signedParams)) != 0)
    goto fail;
    goto fail;  // <--- duplicate! always jumps, skips signature check
if ((err = SSLHashSHA1.final(&hashCtx, &hashOut)) != 0)
    goto fail;
```

### Timing Attacks
`String.equals()` returns `false` as soon as it finds the first mismatch. An attacker measuring response times can infer *how many characters of a secret they've guessed correctly* — turning an O(62^32) brute-force into O(62×32).

---

## ⚠️ Vulnerable Code Examples

See [`VulnerableAuthService.java`](code/VulnerableAuthService.java) — demonstrates:
1. `==` used for String comparison (CWE-697)
2. NULL bypass via `||` short-circuit
3. Off-by-one loop boundary
4. Short-circuit skipping security functions
5. Switch fall-through privilege escalation
6. Timing-unsafe secret comparison (CWE-208)

---

## ✅ Secure Code Examples

See [`SecureAuthService.java`](code/SecureAuthService.java) — demonstrates:
1. `.equals()` with Yoda conditions
2. Explicit null guard before field access
3. Correct loop boundary (`<` not `<=`)
4. Decoupled security function calls
5. Switch with `return` (no fall-through)
6. `MessageDigest.isEqual()` for constant-time comparison

See [`SecureComparison.java`](code/SecureComparison.java) — dedicated timing-safe comparison utility.

See [`RoleEnum.java`](code/RoleEnum.java) — type-safe role model using Java enums.

---

## 💡 Key Takeaways

- **Never use `==` for Strings in Java** — use `.equals()` or Yoda conditions (`"literal".equals(var)`)
- **Short-circuit can silently skip security calls** — separate mandatory security functions from boolean expressions
- **Switch fall-through is a silent privilege escalation risk** — use `return` or document intentional fall-through
- **`String.equals()` is timing-unsafe for secrets** — use `MessageDigest.isEqual()` for tokens, HMAC values, API keys
- **Fail closed, not open** — when a security check is ambiguous, deny access as the default

---

## 🏋️ Mini Challenge

Fix all the bugs in `LoginControllerChallenge.java` — see [`code/LoginControllerChallenge.java`](code/LoginControllerChallenge.java).

**Bugs to find:**
1. Switch fall-through (is it intentional and documented?)
2. Logic inversion: `user == null || user.getPassword().equals(password)` — accepts null users!
3. Plaintext password comparison (should use hash comparison)
4. `headerToken.equals()` throws NPE if header is absent
5. Timing-unsafe token comparison

---

## ❓ Quick Quiz

**Q1.** What does `checkRole("guest")` return if `switch` has no `break` after `case "guest"` or `case "user"`?
- a) `"G"`
- b) `"GUA"` ✅
- c) `"G U A"`
- d) Throws an exception

**Q2.** You're comparing a CSRF token. Which approach is safe?
- a) `return csrfToken.equals(storedToken);`
- b) `return csrfToken == storedToken;`
- c) `return MessageDigest.isEqual(csrfToken.getBytes(), storedToken.getBytes());` ✅
- d) `return csrfToken.hashCode() == storedToken.hashCode();`

**Q3.** In `if (logRequest(req) && isAuthenticated(req))`, what's the bug?
- a) `logRequest()` is called even for unauthenticated requests
- b) Both always run — no bug
- c) If `logRequest()` returns `false`, auth check is skipped entirely ✅
- d) `&&` guarantees both always run

---

## 📚 Resources

- [Apple CVE-2014-1266 Analysis](https://www.imperialviolet.org/2014/02/22/applebug.html)
- [Remote Timing Attacks are Practical (Paper)](https://www.cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)
- [Java MessageDigest.isEqual() Docs](https://docs.oracle.com/en/java/docs/api/java.base/java/security/MessageDigest.html)
