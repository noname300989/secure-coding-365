# Day 16: Error Handling & Secure Logging (PHP)

**Phase 1 — Programming Foundations & Setup | Module: PHP Foundations**

---

## 🎯 What You'll Learn

- Why `display_errors = On` in production exposes your internals to attackers
- How to write a custom exception handler that logs everything but reveals nothing
- How to integrate **Monolog** for structured, leveled, secure logging
- What to log, what NOT to log (PII, passwords, tokens)
- PHP's error-to-exception bridging with `set_error_handler()`
- How to detect and prevent log injection (CWE-117)

---

## 🌍 Real-World Context

Error messages are a goldmine for attackers. In 2017, Equifax's breach was partly enabled by verbose error traces leaking stack paths and framework versions. In 2022, several Laravel apps had `APP_DEBUG=true` in production, exposing database credentials in browser error pages.

**OWASP Top 10 A09:2021 — Security Logging and Monitoring Failures** specifically calls out insufficient logging as a systemic risk. Applications that don't log auth failures, high-value transactions, and errors cannot detect breaches in progress.

---

## CWEs Covered

| CWE | Name | Risk |
|-----|------|------|
| CWE-209 | Information Exposure Through Error Message | Attacker learns internal paths, DSN, framework version |
| CWE-532 | Insertion of Sensitive Information into Log File | Logged passwords/tokens create a secondary breach surface |
| CWE-117 | Improper Output Neutralization for Logs | Log injection corrupts integrity and fools SIEM/security teams |

---

## ⚠️ The Vulnerable Way

See: `code/vulnerable_error_handling.php`

**Issues:**
1. `display_errors = 1` exposes full stack trace (with DSN password!) in the browser
2. No custom exception handler — PHP default renderer shows everything
3. Logging the full credit card number to plain log file (CWE-532)
4. `echo`ing exception message directly to user (CWE-209)
5. Unsanitized username written to log allows newline injection (CWE-117)

---

## ✅ The Secure Way

See:
- `code/bootstrap_error_handler.php` — Custom exception + error handler with Monolog
- `code/SecurePaymentService.php` — Masked PAN logging
- `code/SecureAuthService.php` — Log injection prevention

**Key principles:**
- `display_errors = Off`, `log_errors = On` in production php.ini
- `set_exception_handler()` logs full detail internally, returns generic 500 to user
- `set_error_handler()` bridges PHP warnings/notices to exceptions
- Monolog `RotatingFileHandler` prevents disk exhaustion
- `JsonFormatter` makes logs machine-parseable for SIEM/ELK ingestion
- Mask sensitive fields before logging: PAN → last 4 digits
- Strip `\r\n\t` from user-controlled log inputs

---

## 💡 Key Takeaways

- **Never display errors in production** — Log everything, show nothing (CWE-209)
- **Use set_exception_handler() + set_error_handler() together** — single handler catches all PHP errors and exceptions
- **Monolog is the standard** — RotatingFileHandler + JsonFormatter + IntrospectionProcessor
- **Mask sensitive data before logging** — passwords never, PAN → last 4, tokens → first 8 chars
- **Prevent log injection (CWE-117)** — strip `\r\n\t` from user input; JSON formatter also escapes newlines

---

## 🏋️ Mini Challenge

Given this vulnerable snippet:

```php
ini_set('display_errors', 1);
function resetPassword(string $email, string $newPass): void {
    $pdo = new PDO('mysql:host=localhost;dbname=shop', 'root', 'admin123');
    $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE email = ?");
    $stmt->execute([$newPass, $email]);
    error_log("Password reset for $email to: $newPass at " . date('Y-m-d'));
    echo "Password updated to: $newPass";
}
resetPassword($_GET['email'], $_GET['pass']);
```

1. List all security issues (at least 5)
2. Rewrite using Monolog, production-safe
3. What should be logged? What response to the user?
4. Bonus: What PHP function hashes the password before storing?

---

## ❓ Quick Quiz

**Q1.** In PHP production, which combination is correct?
- a) display_errors=On, log_errors=On
- b) display_errors=Off, log_errors=Off
- **c) display_errors=Off, log_errors=On ✅**
- d) display_errors=On, log_errors=Off

**Q2.** Which SHOULD you log on auth failure?
- a) The password they entered
- b) Their session ID
- **c) Username, IP address, timestamp, and failure reason ✅**
- d) Nothing

**Q3.** Injecting `admin\nINFO: Login success for: root` into a log is called:
- a) XSS
- **b) Log Injection (CWE-117) ✅**
- c) SSRF
- d) CSRF

**Q4.** Monolog's RotatingFileHandler is important primarily because:
- a) It encrypts log files
- **b) It limits log file growth to prevent disk exhaustion ✅**
- c) It sends logs to multiple destinations
- d) It masks sensitive fields

---

## 📚 Bonus Resources

- [Monolog GitHub](https://github.com/Seldaek/monolog)
- [OWASP A09:2021 — Security Logging & Monitoring](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [CWE-209: Information Exposure Through Error Message](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [CWE-532: Sensitive Information in Log File](https://cwe.mitre.org/data/definitions/532.html)

---

*Day 16 of 365 — Secure Coding Journey 🛡️*
