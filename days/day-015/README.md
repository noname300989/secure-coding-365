# Day 15: OOP in PHP — Secure Design

**Phase:** Programming Foundations & Setup
**Module:** PHP Foundations
**Language:** PHP

---

## 🎯 What You'll Learn

- Why **visibility** (`public`/`protected`/`private`) is a security boundary, not just style
- How **traits** can introduce subtle security bugs through shared mutable state
- Using **interfaces** as security contracts your code must honour
- Building **immutable value objects** that can't be tampered with after creation
- **Secure constructor patterns**: validate at construction time so invalid state is impossible
- PHP 8.1 `readonly` properties and constructor promotion for bulletproof design

---

## 🌍 Real-World Context

In 2022, a popular PHP e-commerce platform had a vulnerability where an **attacker modified a Money object's amount after construction** — turning a $1 cart into a $1,000 credit. Root cause: the `Money` class had `public` properties that any code could overwrite.

This is **CWE-501: Trust Boundary Violation** — internal domain objects trusted external input without re-validation.

**CWEs Referenced:**
- [CWE-1061](https://cwe.mitre.org/data/definitions/1061.html) — Insufficient Encapsulation
- [CWE-501](https://cwe.mitre.org/data/definitions/501.html) — Trust Boundary Violation
- [CWE-20](https://cwe.mitre.org/data/definitions/20.html) — Improper Input Validation

---

## ⚠️ Vulnerable Code

See [`code/VulnerableBankAccount.php`](code/VulnerableBankAccount.php)

**Problems:**
- `public` properties — any code can overwrite `$balance`, `$owner`, `$isFrozen`
- No constructor validation — negative balances are representable
- Negative withdrawals act as deposits (no amount validation)
- `isFrozen` bypass — caller can set it to `false` directly

---

## ✅ Secure Code

See [`code/Money.php`](code/Money.php) and [`code/SecureBankAccount.php`](code/SecureBankAccount.php)

**Fixes:**
- `private` / `readonly` properties — language enforces encapsulation
- `final` class — no malicious subclass can override `withdraw()`
- Constructor validation — invalid `Money` or `BankAccount` cannot be constructed
- Immutable `Money` value object — operations return new objects; no in-place mutation
- `Auditable` interface — every account must expose an audit log

---

## 🏋️ Mini Challenge

Build a secure `EmailAddress` value object:

1. Constructor accepts `string $email`
2. Validate with `filter_var($email, FILTER_VALIDATE_EMAIL)` — throw `InvalidArgumentException` on failure
3. Normalize to lowercase in constructor
4. Expose via `getValue(): string` getter only (no public properties)
5. Add `equals(EmailAddress $other): bool`
6. Make the class `final` and property `readonly`
7. **Bonus**: `getDomain(): string` returns the domain portion

See [`code/EmailAddressChallenge.php`](code/EmailAddressChallenge.php) for the starter template.

---

## ❓ Quick Quiz

**Q1.** A `BankAccount` class has `public float $balance`. What CWE does this violate?
- a) CWE-20 (Improper Input Validation)
- **b) CWE-1061 (Insufficient Encapsulation)** ✅
- c) CWE-190 (Integer Overflow)
- d) CWE-116 (Improper Encoding)

**Q2.** You want `$createdAt` set once, never changed. Best PHP 8.1+ approach?
- a) `protected DateTime $createdAt`
- b) `public static $createdAt`
- **c) `public readonly \DateTimeImmutable $createdAt`** ✅
- d) `private $createdAt` with a setter

**Q3.** A trait has `public static int $requestCount = 0`. Why is this risky in PHP-FPM?
- a) Static properties are slower
- **b) In long-running FPM workers, static state persists across requests — user A's data contaminates user B** ✅
- c) PHP traits don't support static properties
- d) It causes integer overflow

---

## 💡 Key Takeaways

1. **Default to `private`** — every public property is an attack surface (CWE-1061)
2. **Make domain objects immutable** — use `readonly` + return new objects from operations
3. **Validate in constructors** — make illegal states unrepresentable
4. **Use `final`** on security-critical classes — prevents override attacks
5. **Traits = behaviour only** — avoid static/shared mutable state in traits
6. **Interfaces as security contracts** — `Auditable`, `Sanitizable`, `AccessControlled`

---

## 📊 Progress

**15 / 365 days — 4.1% complete**
`████░░░░░░░░░░░░░░░░`
