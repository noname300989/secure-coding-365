# Day 4: Arrays & Strings — Secure Handling

**Phase:** Programming Foundations & Setup  
**Module:** Java Foundations  
**Language:** Java  
**Date:** 2026-04-20  

---

## 🎯 What You'll Learn

- Why array index errors cause real-world breaches
- How Java's String immutability can **work against you** when handling passwords
- The security-critical difference between `String` and `char[]` for secrets
- Safe patterns for string building/concatenation in security-sensitive code
- **CWEs Covered:** CWE-125, CWE-129, CWE-193, CWE-209, CWE-256

---

## 🌍 Real-World Context

Arrays and strings are the most basic data structures in any language — but they're responsible for some of the most devastating vulnerabilities in history.

**Heartbleed (CVE-2014-0160)** — one of the worst security flaws ever disclosed — was fundamentally an array bounds violation in OpenSSL's C code. It leaked private server keys, passwords, and sensitive memory from thousands of servers worldwide.

In Java, garbage collection protects you from low-level buffer overflows, but you still face:

1. **ArrayIndexOutOfBoundsException** from unchecked user-supplied indices (CWE-129). Attackers probe with boundary values (0, -1, `Integer.MAX_VALUE`, array.length).
2. **String immutability** means passwords linger in memory — a heap dump or crash dump will contain them in plaintext. Java's own security guidelines and NIST 800-63B explicitly say: *never store passwords in a `String`.*
3. **String concatenation in loops** can leak sensitive fragments into logs or exception messages.

---

## ⚠️ Vulnerable Code

See [`VulnerableStringArrayHandler.java`](code/VulnerableStringArrayHandler.java)

**Issues demonstrated:**
- No bounds checking on user-supplied array index (CWE-129)
- Password stored and compared as `String` — cannot be zeroed, timing-unsafe (CWE-256)
- Sensitive data concatenated into log messages (CWE-209)
- Off-by-one loop error (`<=` instead of `<`) causing ArrayIndexOutOfBoundsException (CWE-193)

---

## ✅ Secure Code

See [`SecureStringArrayHandler.java`](code/SecureStringArrayHandler.java) and [`SecureStringBuilder.java`](code/SecureStringBuilder.java)

**Fixes applied:**
- Explicit bounds validation: `index >= 0 && index < array.length`
- `char[]` for passwords with `Arrays.fill(..., '\0')` in `finally` block
- Constant-time XOR comparison to prevent timing attacks
- Log counts/operations, never log actual data values
- Correct loop boundary: `i < array.length`
- Generic error messages that don't reveal internal structure

---

## 💡 Key Takeaways

- **Always validate array indices from user input** — check `index >= 0 && index < array.length` before every access
- **Never store passwords in a `String`** — use `char[]` so you can zero it out with `Arrays.fill()` immediately after use
- **Constant-time comparison is essential for secrets** — use XOR-based comparison or `MessageDigest.isEqual()` to prevent timing side-channels
- **Log operations, not data** — log what you did, not what the data was
- **Off-by-one errors (`<=` vs `<`) are security bugs** — Heartbleed was caused by this exact class of mistake

---

## 🏋️ Mini Challenge

See [`PINVerifierChallenge.java`](code/PINVerifierChallenge.java)

Rewrite a broken PIN verification method to:
1. Accept `char[]` instead of `String`
2. Implement constant-time comparison
3. Zero out the char array in a `finally` block
4. Add input validation (null check, length=4, digits only)

**Bonus:** What changes if the PIN is a bcrypt hash?

---

## ❓ Quick Quiz

**Q1.** Why should passwords be stored as `char[]` rather than `String` in Java?  
→ **b)** Strings are immutable and cannot be zeroed from memory, but `char[]` can be overwritten

**Q2.** What is the security impact of using `String.equals()` to compare secrets?  
→ **c)** It enables timing attacks because it short-circuits at the first mismatched character

**Q3.** Which loop is correct for iterating a `String[] roles` of length 5?  
→ **c)** `for (int i = 0; i < roles.length; i++)`

---

## 📚 Resources

- [Arrays.fill() JavaDoc](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/Arrays.html#fill(char%5B%5D,char))
- [Oracle Secure Coding Guidelines for Java SE](https://www.oracle.com/java/technologies/javase/seccodeguide.html) — Guideline 2-3
- [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)
- [Heartbleed.com](https://heartbleed.com) — the definitive post-mortem
