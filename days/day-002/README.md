# Day 2/365 — Variables, Data Types & Type Safety

**Phase:** Programming Foundations & Setup
**Module:** Java Foundations
**Language:** Java
**Date:** 2026-04-18

---

## 🎯 What You'll Learn

- Why type safety matters for security
- How integer overflow/underflow silently corrupts programs
- Why autoboxing `null` crashes applications
- How type confusion bugs open the door to exploits
- Best practices for safe numeric handling in Java

---

## 🌍 Real-World Context

**Case Study 1 — Ariane 5 Rocket Explosion (1996):**
The European Space Agency's Ariane 5 rocket exploded 37 seconds into its maiden flight. A 64-bit floating-point number was converted to a 16-bit signed integer, and the value was too large — causing an unhandled overflow exception that crashed the guidance computer. $500 million lost.

**Case Study 2 — Android Bitcoin Wallet Hack (2013-2014):**
A flaw in Java's `SecureRandom` was combined with integer arithmetic bugs to steal Bitcoin from Android wallets.

**Case Study 3 — CVE-2016-5195 (Dirty COW):**
Root cause partially involved incorrect type size assumptions — integer sizes and pointer types were assumed to match but didn't.

---

## ⚠️ The Vulnerable Way (DON'T do this)

See `code/VulnerableBank.java` and `code/VulnerableInventory.java`

### Problem 1: Integer Overflow
```java
private int balance = 2_000_000_000;

public void deposit(int amount) {
    balance += amount; // Silent overflow! Can wrap to negative
}
```
**CWE-190:** Integer Overflow or Wraparound

### Problem 2: Autoboxing Null + Type Confusion
```java
int currentStock = stockLevels.get(item); // NPE if item not in map!
return stock == 1000; // == compares references, not values — unreliable!
return (byte) total; // Silently truncates if total > 127
```
**CWE-476:** NULL Pointer Dereference  
**CWE-704:** Incorrect Type Conversion or Cast

---

## ✅ The Secure Way (DO this)

See `code/SecureBank.java` and `code/SecureInventory.java`

### Fix 1: Math.addExact() and BigDecimal
```java
// Throws ArithmeticException on overflow — never silent
balanceCents = Math.addExact(balanceCents, amountCents);

// BigDecimal for exact money representation
BigDecimal amount = new BigDecimal(amountStr)
        .setScale(2, RoundingMode.HALF_EVEN);
```

### Fix 2: Safe null handling and comparison
```java
int currentStock = stockLevels.getOrDefault(item, 0); // No NPE
return stock.equals(1000); // .equals() compares VALUE, always reliable
```

---

## 💡 Key Takeaways

- **Integer overflow is silent** — `int max + 1` wraps to `int min`. Use `Math.addExact()` or `long`/`BigDecimal`.
- **Never use `==` for Integer objects** — JVM only caches -128 to 127. Use `.equals()`.
- **Unboxing `null` throws NullPointerException** — use `getOrDefault()`, null checks, or `Optional`.
- **Cast order matters** — `(long)(a * b)` overflows first; `(long) a * b` multiplies in long space.
- **Never use float/double for money** — `0.1 + 0.2 == 0.30000000000000004`. Use `BigDecimal`.

---

## 🏋️ Mini Challenge

Fix the broken `PrizeSplitter` class in `code/PrizeSplitterChallenge.java`. Find all 3 bugs:
1. Division by zero risk
2. Integer overflow risk
3. What else?

---

## ❓ Quick Quiz

**Q1:** What is the output of `int x = Integer.MAX_VALUE; x = x + 1; System.out.println(x);`?
- a) 2147483648
- b) ArithmeticException
- c) **-2147483648** ✅
- d) 0

**Q2:** Which correctly compares two `Integer` objects for value equality in ALL cases?
```java
Integer a = 500; Integer b = 500;
```
- a) `a == b`
- b) `a.equals(b)` ✅
- c) `(int) a == (int) b`
- d) **Both b) and c)** ✅

**Q3:** Safest way to represent `"19.99"` as a monetary value in Java?
- a) `Float.parseFloat(amountStr)`
- b) `Double.parseDouble(amountStr)`
- c) **`new BigDecimal(amountStr)`** ✅
- d) `(int)(Double.parseDouble(amountStr) * 100)`

---

## 📚 Relevant CWEs

- CWE-190: Integer Overflow or Wraparound
- CWE-191: Integer Underflow
- CWE-476: NULL Pointer Dereference
- CWE-704: Incorrect Type Conversion or Cast
- CWE-681: Incorrect Conversion between Numeric Types

## 📖 Resources

- [CWE-190: Integer Overflow](https://cwe.mitre.org/data/definitions/190.html)
- *Effective Java* by Joshua Bloch — Item 61: "Prefer primitive types to boxed primitives"
- Java docs: `java.lang.Math` — `addExact()`, `subtractExact()`, `multiplyExact()`
- Java docs: `java.math.BigDecimal`
