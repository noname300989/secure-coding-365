# Day 8: Exception Handling & Secure Error Management

**Phase:** Programming Foundations & Setup  
**Module:** Java Foundations  
**Language:** Java  
**Date:** 2026-04-24  

---

## 🎯 What You'll Learn

- Why stack traces and raw exception messages are a hacker's treasure map
- The difference between *logging for developers* vs *responding to users*
- How to write custom exceptions that don't leak internals
- Secure `try/catch/finally` patterns that close resources properly
- CWE-209, CWE-390, and real-world breach examples rooted in poor error handling

---

## 🌍 Real-World Context

### CVE-2017-9805 — Apache Struts (Equifax Breach Context)
The 2017 Equifax breach (147 million Americans' data exposed) was enabled partly by verbose error messages revealing internal framework details and paths. Attackers read error responses to map the server's structure before launching RCE exploits.

### CWE-209: Information Exposure Through an Error Message
Your catch block prints a stack trace to the HTTP response. That trace tells attackers:
- What Java framework/version you're running (`at org.springframework.web.servlet...`)
- Your internal package structure (`at com.mybank.internal.db.UserDAO.findUser`)
- Your database type and query (`java.sql.SQLException: ORA-01722: invalid number`)
- Your server file paths (`at /opt/tomcat9/webapps/app/...`)

**The Rule of Thumb:**
- What the user sees → generic, safe, helpful message + correlation ID
- What the log sees → full stack trace with context, correlation ID
- Never the same. Never mixed.

---

## ⚠️ Vulnerable Code

See `VulnerableUserController.java` — demonstrates:
1. `e.getMessage()` returned in HTTP response body (leaks DB internals)
2. `e.printStackTrace()` output sometimes captured in response
3. Full stack trace in HTTP body via `StringWriter`
4. Silent exception swallowing — CWE-390

## ✅ Secure Code

See `SecureUserController.java` and `GlobalExceptionHandler.java` — demonstrates:
1. Correlation IDs generated server-side (UUID)
2. Internal details logged only; users see safe generic messages
3. Custom exception hierarchy with separate user/internal messages
4. `@ControllerAdvice` global exception handler for consistent responses
5. Try-with-resources for automatic resource cleanup

---

## 💡 Key Takeaways

- **Two audiences, two messages** — Users get a safe, generic message + correlation ID. Logs get the full stack trace. Never mix them.
- **CWE-209** (Info Leakage via Error Message) is trivially exploitable. Never put `e.getMessage()` or stack traces in HTTP responses.
- **CWE-390** (Silent Failure) is equally dangerous — always log and handle exceptions properly.
- **Correlation IDs** let you say "Reference: abc-123" to users and grep logs for exactly what happened.
- **`@ControllerAdvice`** centralises error-response formatting, ensuring consistent security across all endpoints.
- **Try-with-resources** ensures JDBC connections and streams are always closed.

---

## 🏋️ Mini Challenge

Fix the vulnerable `withdraw()` method:
```java
@PostMapping("/accounts/{id}/withdraw")
public String withdraw(@PathVariable String id, @RequestParam String amount) {
    try {
        Account acct = db.getAccount(id);
        BigDecimal amt = new BigDecimal(amount);
        acct.debit(amt);
        db.save(acct);
        return "OK: withdrew " + amount + " from account " + id;
    } catch (Exception e) {
        return "Error: " + e.getMessage() + "\n" + e.getStackTrace()[0];
    }
}
```

Issues to find and fix:
1. Error message leaks internals
2. Stack trace element in response
3. No correlation ID
4. No specific exception handling
5. Success message echoes raw user input
6. No atomicity — `db.save()` could fail after `debit()`

---

## ❓ Quick Quiz

**Q1.** A REST API returns `{"error": "com.company.db.UserDAO: user 'admin' not found in table users_v2"}` — which CWE?  
→ **b) CWE-209 (Information Exposure Through Error Message)** ⭐

**Q2.** Primary purpose of a correlation ID in error handling?  
→ **b) Link a user-visible reference to the full internal log entry without exposing details** ⭐

**Q3.** Which Java pattern ensures DB connections are always closed?  
→ **c) `try-with-resources` using `AutoCloseable`** ⭐

**Q4.** `catch (Exception e) { }` that does nothing is:  
→ **b) CWE-390 Detection of Error Condition Without Action** ⭐

---

## 📚 Resources

- [OWASP Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/)
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-390](https://cwe.mitre.org/data/definitions/390.html)
- [Spring @ControllerAdvice docs](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-ann-controller-advice)
