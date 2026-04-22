# Day 6: OOP Part 1 — Encapsulation as Security

**Phase:** Programming Foundations & Setup  
**Module:** Java Foundations  
**Language:** Java  
**Date:** 2026-04-22  

---

## 🎯 What You'll Learn

- Why access modifiers (`private`, `protected`, `public`) are your first line of defense
- How encapsulation prevents unauthorized data mutation
- Immutable objects: what they are and why they matter for thread safety and security
- Information hiding: keeping internal implementation details secret from attackers
- Real-world security failures caused by broken encapsulation

---

## 🌍 Real-World Context

In 2019, Facebook suffered a breach where hundreds of millions of passwords were stored in plaintext internally — not because of an external hack, but because developers had direct access to raw credential objects across codebases. Poor encapsulation meant sensitive fields were accessible anywhere in the application.

Encapsulation maps directly to real security concepts:

| OOP Concept | Security Principle |
|---|---|
| `private` fields | Principle of Least Privilege |
| Getter-only access | Confidentiality (CIA Triad) |
| Defensive copies | Integrity of internal state |
| Final fields | Immutability / Thread safety |
| Validation in setters | Input validation defense |

---

## ⚠️ The Vulnerable Way (DON'T do this)

See `code/VulnerableBankAccount.java`

**Issues:**
- `balance` is public → any class can do `account.balance = -1_000_000`
- `pin` stored as public `String` → lives in JVM String pool, never garbage-collected
- `getTransactionHistory()` returns the live list → callers can call `.clear()` to erase audit trails
- `setBalance()` has zero validation → accepts negative values or `Double.NaN`
- `accountNumber` exposed in plaintext with no masking

**CWEs Referenced:**
- CWE-668: Exposure of Resource to Wrong Sphere
- CWE-766: Critical Data Element Public Access

---

## ✅ The Secure Way (DO this)

See `code/SecureBankAccount.java`

**Fixes applied:**
- ALL fields are `private`; `accountHolder` and `accountNumber` are `final`
- `char[] pin` replaces `String pin` — can be zeroed with `Arrays.fill()` on `close()`
- `getTransactionHistory()` returns an unmodifiable view of a defensive copy
- All mutations go through validated business methods (`deposit`, `withdraw`)
- `final` on the class prevents subclasses from overriding security checks
- Account number only exposed via masked format: `****-****-1234`

---

## 🔒 Bonus: Truly Immutable Value Object

See `code/ImmutableMoney.java`

- `final` class — no subclassing
- All `final` fields — state cannot change after construction
- Operations return *new* objects, never mutate `this`
- Uses `long` cents instead of `double` to avoid floating-point arithmetic bugs

---

## 💡 Key Takeaways

1. **Always default to `private`** for fields. Expose only what you consciously decide to make public — Principle of Least Privilege.
2. **Return defensive copies**, not live references. Use `Collections.unmodifiableList(new ArrayList<>(list))`.
3. **Prefer `final` fields** for data that shouldn't change after construction — free thread safety.
4. **Sensitive data in `char[]`, not `String`** — `char[]` can be zeroed; `String` objects linger in the JVM pool.
5. **Put validation inside the class** — if callers can set raw field values, all business logic is bypassable.

---

## 🏋️ Mini Challenge

Refactor this broken `UserProfile` class:

```java
public class UserProfile {
    public String email;
    public String passwordHash;
    public int age;
    public List<String> roles = new ArrayList<>();
    public boolean isPremium;

    public void setAge(int age) { this.age = age; }
    public List<String> getRoles() { return roles; }  // bug here!
}
```

**Your task:**
1. Make all fields `private`
2. Add input validation to `setAge()` (age must be 0–150)
3. Fix `getRoles()` to prevent external mutation
4. Add a `hasRole(String role)` method for safe role checking
5. Make `email` immutable (`final`) since it's the user's unique identifier

See `code/UserProfileChallenge.java` for a starter template.

---

## ❓ Quick Quiz

**Q1.** A class has a `private List<String> auditLog`. The getter is `return auditLog;`. What security issue does this create?
- a) Memory leak
- b) ✅ Callers can modify the internal list, potentially erasing audit evidence (CWE-668)
- c) It violates the Single Responsibility Principle only
- d) No issue — the field is already private

**Q2.** Why should PIN/password data be stored as `char[]` instead of `String` in Java?
- a) `char[]` is faster to compare than `String`
- b) ✅ `String` objects may remain in the JVM String pool; `char[]` can be explicitly zeroed after use
- c) `char[]` takes less memory than `String`
- d) There is no difference

**Q3.** Which access modifier gives the *narrowest* visibility in Java?
- a) `protected`
- b) `package-private`
- c) ✅ `private`
- d) `final` *(not an access modifier — it's a mutability modifier)*

---

## 📚 References

- [CWE-668: Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)
- [CWE-766: Critical Data Element Public Access](https://cwe.mitre.org/data/definitions/766.html)
- [OWASP Secure Coding Practices: Data Protection](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- Java Docs: `Collections.unmodifiableList()`

---

*Day 6 of 365 — Secure Coding 365 Program*
