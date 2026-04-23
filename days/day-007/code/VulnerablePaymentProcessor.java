// VulnerablePaymentProcessor.java
// CWE-1055: Multiple Inheritance Hierarchy in Security Framework
// CWE-284: Improper Access Control via override
// Related: CVE-2015-4852 (Apache Commons Collections deserialization gadget chain)

public class VulnerablePaymentProcessor {

    // Base class with security rules
    public boolean authorize(User user, double amount) {
        // Base rule: only admins can process > $10,000
        if (amount > 10_000 && !user.hasRole("ADMIN")) {
            return false;
        }
        return user.isAuthenticated();
    }

    // processPayment calls authorize() via polymorphism — DANGER
    public void processPayment(User user, double amount) {
        if (authorize(user, amount)) {   // <-- polymorphic call — attacker controls this!
            System.out.println("Processing $" + amount + " for " + user.getUsername());
            // ... actual payment logic
        }
    }
}

// An attacker or careless developer creates a subclass:
class FastTrackProcessor extends VulnerablePaymentProcessor {
    @Override
    public boolean authorize(User user, double amount) {
        // "Temporarily" skip limit checks for faster processing
        // This BYPASSES the $10,000 admin authorization check!
        return user.isAuthenticated(); // <-- VULNERABILITY: no amount limit
    }
}

// Demonstration of the exploit:
class VulnerableDemo {
    public static void main(String[] args) {
        // Simulated regular user (not admin)
        User regularUser = new User("alice", false, true);  // not admin, authenticated

        // Attacker/developer uses FastTrackProcessor instead of base class
        VulnerablePaymentProcessor processor = new FastTrackProcessor();

        // This SUCCEEDS even though regularUser is not admin and amount > $10,000
        processor.processPayment(regularUser, 50_000.00);
        // Output: "Processing $50000.0 for alice"
        // SECURITY CONTROL BYPASSED — $50,000 processed without admin authorization!

        // No compile-time warning. No runtime error. Just a missing $50,000.
    }
}

// Simplified User class for example purposes
class User {
    private String username;
    private boolean isAdmin;
    private boolean isAuthenticated;

    public User(String username, boolean isAdmin, boolean isAuthenticated) {
        this.username = username;
        this.isAdmin = isAdmin;
        this.isAuthenticated = isAuthenticated;
    }

    public String getUsername() { return username; }
    public boolean hasRole(String role) { return "ADMIN".equals(role) && isAdmin; }
    public boolean isAuthenticated() { return isAuthenticated; }
}
