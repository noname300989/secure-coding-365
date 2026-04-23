// FastTrackProcessor.java + AdminPaymentProcessor.java
// Safe subclasses of SecurePaymentProcessor
// Demonstrates: constrained inheritance, final class, hook methods

/**
 * Fast-track payment processor.
 * Can ADD extra checks (daily limit), but CANNOT remove the $10k admin rule.
 * This is LSP-compliant: it upholds all parent-class invariants.
 */
public class FastTrackProcessor extends SecurePaymentProcessor {

    private static final double DAILY_LIMIT = 25_000.0;

    @Override
    protected boolean additionalAuthorization(User user, double amount) {
        // ADD a check: enforce a daily spend limit for fast-track
        double dailySpend = user.getDailySpend();
        if (dailySpend + amount > DAILY_LIMIT) {
            return false; // Daily limit exceeded
        }
        return true;
        // NOTE: We CANNOT bypass coreAuthorize() — it already ran before this method
    }

    @Override
    protected void executePayment(User user, double amount) {
        // Fast-track mechanics only — security is already guaranteed by parent
        System.out.println("[FastTrack] Processing $" + amount
            + " for " + user.getUsername() + " via express lane");
        // ... fast-track payment gateway logic
    }
}

// ================================================================

/**
 * Admin-tier payment processor for high-value transactions.
 *
 * Marked FINAL — no one can subclass this.
 * Even if an attacker controls the classpath, they cannot extend this class.
 * This is a key defense against Java deserialization gadget chains.
 */
public final class AdminPaymentProcessor extends SecurePaymentProcessor {

    private static final double MFA_THRESHOLD = 50_000.0;

    @Override
    protected boolean additionalAuthorization(User user, double amount) {
        // Require MFA verification for very large admin transactions
        if (amount > MFA_THRESHOLD) {
            return user.hasMfaVerified();
        }
        return true;
    }

    @Override
    protected void executePayment(User user, double amount) {
        System.out.println("[Admin] High-value payment of $" + amount
            + " processed for " + user.getUsername());
        // ... admin payment gateway logic with enhanced logging
    }
}

// ================================================================
// Demo showing secure behavior:

class SecureDemo {
    public static void main(String[] args) {
        User regularUser = new User("alice", false, true, 0.0, false);
        User adminUser   = new User("bob",   true,  true, 0.0, true);

        SecurePaymentProcessor processor = new FastTrackProcessor();

        // Case 1: Regular user, $500 — SUCCEEDS (within limits)
        processor.processPayment(regularUser, 500.00);

        // Case 2: Regular user, $50,000 — THROWS SecurityException
        // (coreAuthorize blocks it: amount > $10k and user is not ADMIN)
        try {
            processor.processPayment(regularUser, 50_000.00);
        } catch (SecurityException e) {
            System.out.println("Correctly blocked: " + e.getMessage());
        }

        // Case 3: Admin user, $50,000 — SUCCEEDS (admin + MFA verified)
        SecurePaymentProcessor adminProcessor = new AdminPaymentProcessor();
        adminProcessor.processPayment(adminUser, 50_000.00);

        // Case 4: Cannot compile — AdminPaymentProcessor is final
        // class EvilProcessor extends AdminPaymentProcessor { ... }  // COMPILE ERROR
    }
}
