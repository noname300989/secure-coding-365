// SecurePaymentProcessor.java
// Template Method Pattern + final/private for security invariants
// Prevents override attacks (CWE-284, CWE-1055)

/**
 * Secure abstract base class using the Template Method Pattern.
 * Security invariants are FINAL — no subclass can weaken them.
 * Subclasses may only customize the "mechanics", not the security gates.
 */
public abstract class SecurePaymentProcessor {

    // ================================================================
    // PUBLIC API — FINAL: the entire security flow is locked down
    // ================================================================

    /**
     * Process a payment. This method is FINAL:
     * - Core auth runs first, always, unconditionally
     * - Subclass hook runs second (may add restrictions, never remove)
     * - Only then does executePayment() run
     */
    public final void processPayment(User user, double amount) {
        // Step 1: Core authorization — ALWAYS runs, NEVER overrideable
        if (!coreAuthorize(user, amount)) {
            // CWE-209: Don't leak WHY authorization failed to the caller
            throw new SecurityException("Payment authorization failed.");
        }
        // Step 2: Subclass may add extra checks via hook method
        if (!additionalAuthorization(user, amount)) {
            throw new SecurityException("Payment authorization failed.");
        }
        // Step 3: Log the authorization (audit trail)
        auditLog(user, amount);
        // Step 4: Execute the actual payment mechanics (subclass responsibility)
        executePayment(user, amount);
    }

    // ================================================================
    // PRIVATE FINAL: core security rules — invisible to subclasses
    // ================================================================

    /**
     * Core business security rules.
     * PRIVATE + FINAL = no subclass can see or override this.
     * This is the fortress wall around our security invariants.
     */
    private boolean coreAuthorize(User user, double amount) {
        // Rule 1: Must be authenticated
        if (!user.isAuthenticated()) {
            return false;
        }
        // Rule 2: Non-negative amount
        if (amount <= 0) {
            return false;
        }
        // Rule 3: Large amounts require ADMIN role
        if (amount > 10_000 && !user.hasRole("ADMIN")) {
            return false;
        }
        return true;
    }

    /**
     * Audit logging — also final to ensure all payments are logged.
     */
    private void auditLog(User user, double amount) {
        // In production: write to immutable audit log
        System.out.println("[AUDIT] Payment of $" + amount +
            " authorized for user: " + user.getUsername() +
            " at " + java.time.Instant.now());
    }

    // ================================================================
    // PROTECTED HOOKS: subclasses may EXTEND but never REPLACE security
    // ================================================================

    /**
     * Hook for additional authorization checks.
     * Subclasses may ADD restrictions (return false for more cases).
     * They CANNOT remove the core coreAuthorize() check above.
     * Default: no extra checks (base behavior).
     */
    protected boolean additionalAuthorization(User user, double amount) {
        return true;
    }

    // ================================================================
    // ABSTRACT: subclasses MUST implement the mechanics, not security
    // ================================================================

    /**
     * Execute the actual payment using processor-specific mechanics.
     * Security has ALREADY been verified before this is called.
     */
    protected abstract void executePayment(User user, double amount);
}
