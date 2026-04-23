# Day 7: OOP Part 2 — Inheritance & Polymorphism

**Phase:** Programming Foundations & Setup  
**Module:** Java Foundations  
**Language:** Java  
**CWEs Covered:** CWE-1055, CWE-284  
**CVEs Referenced:** CVE-2015-4852, CVE-2016-3510 (Apache Commons Collections deserialization RCE)

---

## What You'll Learn

- Why inheritance is a powerful but dangerous feature if misused
- How attackers exploit unconstrained inheritance to override security-critical behavior
- How to use `final`, sealed hierarchies, and the Liskov Substitution Principle (LSP) defensively
- Real-world CVE context: Java deserialization gadget chains that exploit inheritance
- Pattern: secure abstract base classes that enforce invariants

---

## Real-World Context

Inheritance looks harmless on paper — reuse code, extend behavior, model the real world. But in security, **every overrideable method is an attack surface**.

**Java deserialization (CVE-2015-4852, CVE-2016-3510 — Apache Commons Collections):** Attackers crafted byte streams that, when deserialized, triggered a chain of overridden `equals()`, `hashCode()`, and `compareTo()` methods across innocent-looking class hierarchies. The result? Remote Code Execution on WebLogic, JBoss, and Jenkins servers worldwide.

The root cause: library classes with overrideable methods that performed dangerous operations were freely subclassable and their method dispatch could be hijacked through polymorphism.

**Rule of thumb:** If a class has security-critical logic, design for inheritance consciously — or prevent it entirely with `final`. Joshua Bloch's *Effective Java* Item 19: "Design and document for inheritance, or else prohibit it."

**The Liskov Substitution Principle (LSP) lens:** LSP says if `S extends T`, you should be able to use `S` anywhere `T` is used without breaking correctness. Violating LSP in security code means subclasses can silently weaken invariants — like turning a "user must be authenticated" check into a no-op.

---

## Vulnerable Code

See [`VulnerablePaymentProcessor.java`](code/VulnerablePaymentProcessor.java)

**Problems:**
- `processPayment()` calls `authorize()` via polymorphism — any subclass can reroute it
- `FastTrackProcessor` silently bypasses the $10,000 admin limit
- No compile-time warning. No runtime error. Just missing $50,000.
- Violates LSP: callers of `PaymentProcessor` expect the $10k limit to always hold

---

## Secure Code

See:
- [`SecurePaymentProcessor.java`](code/SecurePaymentProcessor.java) — Template Method Pattern with `final` + `private`
- [`FastTrackProcessor.java`](code/FastTrackProcessor.java) — safe subclass that can only add restrictions
- [`SealedPaymentMethod.java`](code/SealedPaymentMethod.java) — Java 17 sealed hierarchy

**Why it's secure:**
- `processPayment()` is `final` — no subclass can reroute the security flow
- `coreAuthorize()` is `private final` — invisible and untouchable by subclasses
- Template Method Pattern separates invariant (security) from variant (mechanics)
- Sealed classes close the hierarchy — no gadget chain can sneak in a new subtype

---

## Key Takeaways

1. Every overrideable method is an attack surface. Mark security-critical methods `final` or `private`. (CWE-1055, CWE-284)
2. Use the **Template Method Pattern**: keep security orchestration `final` in the parent; expose only narrow hook methods for subclasses.
3. **LSP is a security contract**: a subclass that weakens a precondition (e.g., removes an auth check) violates LSP *and* creates a privilege escalation vulnerability.
4. `final` classes prevent gadget chains — Java deserialization exploits rely on extending library classes. `final` cuts that off.
5. Java 17 `sealed` classes let you own your hierarchy — the compiler enforces it, eliminating extension-based attacks.

---

## Mini Challenge

You're given this insecure hierarchy:

```java
public class Authenticator {
    public boolean authenticate(String username, String password) {
        return database.checkCredentials(username, password);
    }
    public void login(String username, String password) {
        if (authenticate(username, password)) {
            session.createSession(username);
        }
    }
}

public class DevAuthenticator extends Authenticator {
    @Override
    public boolean authenticate(String username, String password) {
        return true; // Always true in dev... oops, deployed to prod
    }
}
```

**Your task:**
1. Identify all the security problems in this hierarchy
2. Rewrite `Authenticator` using Template Method Pattern with `final` on `login()`
3. Add a rate-limiting hook that subclasses can customize (but not bypass)
4. Ensure `DevAuthenticator` can only exist in test scope — what build tooling would you use?
5. **Bonus:** Use Java 17 `sealed` to restrict to `ProductionAuthenticator` and `TestAuthenticator` only

---

## Quick Quiz

1. A junior dev creates `DebugFilter extends SecurityFilter` and overrides `doFilter()` to skip token validation. What is the primary CWE?
   - a) CWE-190 (Integer Overflow)
   - b) **CWE-284 (Improper Access Control via override)** ✅
   - c) CWE-209 (Information Exposure)
   - d) CWE-476 (Null Pointer Dereference)

2. Which modifier combination best prevents a critical security method from being overridden?
   - a) `protected abstract`
   - b) `public static`
   - c) **`public final`** ✅
   - d) `private static`

3. `sealed class PaymentMethod permits CreditCard, BankTransfer` means:
   - a) Subclasses cannot have any methods
   - b) **Only `CreditCard` and `BankTransfer` may extend `PaymentMethod` — enforced at compile time** ✅
   - c) `PaymentMethod` cannot be instantiated
   - d) All subclasses must be in the same package

---

## Progress: 7/365 days (1.9%)

**Next:** Day 8 — Exception Handling & Secure Error Management (CWE-209, CWE-390)
