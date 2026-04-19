// SECURE: Overflow-safe financial logic using Java 8+ exact math
// Uses Math.addExact() and BigDecimal for safe monetary operations
import java.math.BigDecimal;
import java.math.RoundingMode;

public class SecureBank {

    // Use long instead of int for large monetary values
    // Even better: use BigDecimal for money
    private long balanceCents = 200_000_000_00L; // $2 billion in cents

    // Option A: Use Math.addExact() — throws ArithmeticException on overflow
    public void depositLong(long amountCents) {
        try {
            balanceCents = Math.addExact(balanceCents, amountCents);
        } catch (ArithmeticException e) {
            throw new IllegalStateException(
                "Deposit would cause balance overflow", e);
        }
    }

    // Option B (BEST for money): BigDecimal — no overflow, no float imprecision
    private BigDecimal preciseBalance = new BigDecimal("2000000000.00");

    public void depositBigDecimal(String amountStr) {
        // Parse from String to avoid float precision issues
        BigDecimal amount = new BigDecimal(amountStr)
                .setScale(2, RoundingMode.HALF_EVEN); // Banker's rounding

        if (amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Deposit must be positive");
        }

        preciseBalance = preciseBalance.add(amount);
    }

    // Overflow-safe range check
    public boolean canWithdraw(long amountCents) {
        if (amountCents <= 0) return false;
        return balanceCents >= amountCents; // Safe: both long, no overflow risk
    }

    public static void main(String[] args) {
        SecureBank bank = new SecureBank();
        try {
            bank.depositLong(20_000_000_00L); // $200 million in cents
            System.out.println("Deposit succeeded safely");
        } catch (IllegalStateException e) {
            System.out.println("Overflow prevented: " + e.getMessage());
        }

        // BigDecimal precision demo
        // float/double: 0.1 + 0.2 = 0.30000000000000004
        System.out.println("Float: " + (0.1f + 0.2f));
        System.out.println("Double: " + (0.1 + 0.2));
        System.out.println("BigDecimal: " + new BigDecimal("0.1").add(new BigDecimal("0.2")));
    }
}
