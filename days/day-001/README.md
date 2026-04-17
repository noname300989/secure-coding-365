# Day 1: Dev Environment Setup & Security Mindset

> **Phase:** Programming Foundations & Setup | **Module:** Java Foundations | **Stack:** Java
> **Date:** 2026-04-17

---

## 🎯 What You'll Learn

- Why security starts at the development environment level
- How to configure your JDK and IDE securely
- The CIA Triad — the three pillars of information security
- How to write a "secure" Hello World (yes, even that matters!)
- The Secure Development Lifecycle (SDL) mindset

---

## 🌐 Real-World Context: Why Environment Security Matters

In 2021, the Apache Log4Shell vulnerability (CVE-2021-44228) — one of the worst in history — was exploitable partly because developers had Log4j 2.x on their *development machines* and it ended up in production. Attackers scanned for it within *hours* of disclosure.

Your dev environment is the birthplace of your software. Insecure tools, outdated SDKs, misconfigured IDEs, and bad habits formed on Day 1 will follow your code all the way to production.

### The CIA Triad

The CIA Triad is your north star:

- **C — Confidentiality:** Sensitive data (passwords, keys, PII) must not be exposed
- **I — Integrity:** Data and code must not be tampered with
- **A — Availability:** Systems must remain usable; crashes and downtime are security failures too

Every piece of code you write affects at least one of these three. Starting now, ask yourself: *Does my code protect confidentiality, integrity, and availability?*

---

## ⚠️ The Vulnerable Way (DON'T do this)

Here's a typical "beginner" Hello World that seems harmless but embeds insecure habits:

```java
// BAD: InsecureHello.java
public class InsecureHello {

    // ❌ Hardcoded credentials in source code
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-abc123xyz789";

    public static void main(String[] args) {
        // ❌ Printing to stdout with no thought — in production,
        // stdout often goes to logs that attackers can access
        System.out.println("Hello, World!");

        // ❌ Printing sensitive data — this ends up in logs!
        System.out.println("Connecting with password: " + DB_PASSWORD);
        System.out.println("API Key: " + API_KEY);

        // ❌ No error handling — stack traces expose internal paths,
        // class names, library versions to attackers
        String result = null;
        System.out.println(result.length()); // NullPointerException!
    }
}
```

### Why it's dangerous:

- **Hardcoded secrets** end up in Git repos — GitHub is littered with accidentally committed API keys (thousands of secrets exposed daily)
- **Printing sensitive data** to stdout/logs is a classic data leak vector
- **Unhandled exceptions** expose stack traces — attackers learn your library versions and internal paths from them
- This mindset — "it's just Hello World" — is how bad habits are born

---

## ✅ The Secure Way (DO this)

```java
// GOOD: SecureHello.java
import java.util.logging.Logger;
import java.util.logging.Level;

public class SecureHello {

    // ✅ Use a proper logger instead of System.out.println
    private static final Logger LOGGER =
        Logger.getLogger(SecureHello.class.getName());

    // ✅ NEVER hardcode secrets. Load from environment variables.
    // In production: use AWS Secrets Manager, HashiCorp Vault, etc.
    private static String getDbPassword() {
        String password = System.getenv("DB_PASSWORD");
        if (password == null || password.isEmpty()) {
            throw new IllegalStateException(
                "DB_PASSWORD environment variable not set");
        }
        return password;
    }

    public static void main(String[] args) {
        // ✅ Log at appropriate level — INFO for normal flow
        LOGGER.info("Application starting...");

        System.out.println("Hello, Secure World!");

        // ✅ Use try-catch — catch specific exceptions,
        // log them safely (no stack trace to end user)
        try {
            String dbPassword = getDbPassword();
            // ✅ NEVER log the actual secret value!
            LOGGER.info("DB credentials loaded successfully");

            // Simulate some work
            processData(null);

        } catch (IllegalStateException e) {
            // ✅ Log full details internally for debugging
            LOGGER.log(Level.SEVERE,
                "Configuration error: " + e.getMessage(), e);
            // ✅ Show only generic message externally
            System.err.println("Application configuration error. " +
                "Contact your administrator.");
            System.exit(1);
        } catch (Exception e) {
            // ✅ Catch unexpected errors — fail securely
            LOGGER.log(Level.SEVERE, "Unexpected error", e);
            System.err.println("An unexpected error occurred.");
            System.exit(1);
        }

        LOGGER.info("Application finished successfully.");
    }

    private static void processData(String data) {
        // ✅ Validate inputs before using them
        if (data == null) {
            throw new IllegalArgumentException(
                "data must not be null");
        }
        System.out.println("Processing: " + data.length() + " chars");
    }
}
```

### Why it's secure:

- **Secrets from environment variables** — not in source code, not in Git
- **Proper logging framework** — `java.util.logging` (or use SLF4J/Logback in real projects) with configurable levels
- **Generic error messages externally, detailed logs internally** — attackers don't see your internals
- **Input validation** before using data — `null` checks prevent NullPointerExceptions
- **Fail securely** — `System.exit(1)` with a clean message rather than a crash dump

---

## 🛠️ Secure IDE & JDK Setup Checklist

### JDK Setup
- Install LTS version: JDK 21 (current LTS as of 2024)
- Download ONLY from official source: https://adoptium.net
- Verify the SHA256 checksum of the installer before running!
- Keep JDK updated — subscribe to: https://openjdk.org/groups/vulnerability/

### IDE (IntelliJ IDEA / VS Code) Security Settings
- Enable: Editor > Inspections > Security (IntelliJ)
- Install SpotBugs / Find Security Bugs plugin
- Install SonarLint plugin — scans for vulnerabilities as you type!
- Disable auto-import of untrusted projects (IntelliJ: Trust Project prompt)

### Git Security
- Install: `git-secrets` (prevents committing AWS keys, etc.)
  ```bash
  brew install git-secrets  # Mac
  ```
- Add to every repo:
  ```bash
  git secrets --install && git secrets --register-aws
  ```
- Add a `.gitignore` with: `.env`, `*.key`, `*.pem`, `secrets/`, `credentials*`
- Never use: `git add .` — always use: `git add <specific-files>`

### Environment Variables
- Mac/Linux: Add secrets to `~/.zshrc` or `~/.bashrc`
  ```bash
  export DB_PASSWORD="yourpassword"
  ```
- Use a `.env` file for local dev with the `dotenv` library
- Add `.env` to `.gitignore` IMMEDIATELY

### Dependency Management (Maven/Gradle)
- Lock dependency versions in `pom.xml` / `build.gradle`
- Run: `mvn dependency:check` (OWASP plugin) to scan for CVEs
- Plugin for pom.xml:
  ```xml
  <dependency>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.0</version>
  </dependency>
  ```

---

## 💡 Key Takeaways

1. **Security starts at Day 0** — your dev environment, IDE, and habits form the foundation. Bad habits established now compound over time.
2. **Never hardcode secrets** — use environment variables locally, and secrets managers (AWS Secrets Manager, HashiCorp Vault) in production. Treat every string literal in your code as potentially visible in a public Git repo.
3. **The CIA Triad is your compass** — before shipping any feature, ask: does this protect Confidentiality, Integrity, and Availability?
4. **Use a logging framework, never `System.out.println` for production code** — proper loggers give you level control, structured output, and keep secrets out of logs.
5. **Fail securely** — when errors happen, show generic messages to users and log detailed info internally. Never expose stack traces, file paths, or library versions to end users.

---

## 🏋️ Mini Challenge

Complete all three tasks:

1. **Create a secure `App.java`** that:
   - Reads a `SECRET_KEY` from an environment variable (throw an error if missing)
   - Uses `java.util.logging.Logger` to log "App started" at INFO level
   - Has a method `validateInput(String s)` that throws `IllegalArgumentException` if `s` is null or empty
   - Wraps everything in try/catch that logs errors but shows generic messages

2. **Create a `.gitignore`** for a Java project that ignores: `.env`, `*.class`, `target/`, `*.jar`, `*.key`, `*.pem`, `credentials*`

3. **Set an environment variable** on your machine: `export MY_FIRST_SECRET="hello-secure-world"` and read it in your Java app

**Bonus:** Install the SonarLint plugin in your IDE and run it on your code!

---

## ❓ Quick Quiz

**Q1.** You're writing a Java app that connects to a database. Where should you store the database password?

a) As a `static final String` constant in your main class
b) In a `config.properties` file committed to Git
c) In an environment variable or secrets manager, loaded at runtime
d) In a comment at the top of the file for easy reference

**Q2.** Your Java application crashes with an exception. What's the secure approach?

a) Print the full stack trace to the HTTP response so developers can debug easily
b) Catch the exception, log full details internally, and show only a generic error message to the user
c) Ignore the exception with an empty catch block so the app keeps running
d) Print `e.getMessage()` to the user — it's just the message, not the full trace

**Q3.** Which of the following is a violation of the *Confidentiality* pillar of the CIA Triad?

a) A server crashing due to unhandled input (denial of service)
b) An attacker modifying a database record
c) An application logging user passwords in plaintext to a log file
d) A memory leak causing the application to slow down

---

**Answers:** Q1: **c** | Q2: **b** | Q3: **c**

- Q1: Never put secrets in code. Even `private static final` constants end up in compiled `.class` files and Git history.
- Q2: Showing stack traces externally is a real vulnerability — classified as CWE-209 (Information Exposure Through Error Message).
- Q3: Logging passwords violates Confidentiality. (a) is Availability, (b) is Integrity, (d) is Availability.

---

## 📊 Progress: 1/365 days — 0.3% complete

---

## 📚 Bonus Resources

- [OWASP Secure Coding Practices Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CWE-209: Information Exposure Through Error Message](https://cwe.mitre.org/data/definitions/209.html)
- [git-secrets tool](https://github.com/awslabs/git-secrets)
- [SonarLint IDE plugin](https://www.sonarsource.com/products/sonarlint/)
