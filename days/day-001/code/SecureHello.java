// GOOD: SecureHello.java
// Day 1 — The secure approach

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
