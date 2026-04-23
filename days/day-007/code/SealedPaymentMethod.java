// SealedPaymentMethod.java
// Java 17+ sealed class hierarchy for secure type control
// Prevents unknown subclasses — eliminates extension-based attack surface

/**
 * Sealed class: only CreditCard, BankTransfer, and CryptoPayment
 * may extend PaymentMethod. The compiler enforces this exhaustively.
 *
 * Security benefit: no attacker-controlled class can sneak into this hierarchy.
 * Deserialization gadget chains cannot add new subtypes.
 */
public sealed class PaymentMethod
    permits CreditCard, BankTransfer, CryptoPayment {

    // Invariant: every PaymentMethod must be validatable and must mask its ID
    public abstract boolean validate();
    public abstract String getMaskedId();

    /**
     * Use pattern matching switch (Java 17+) — compiler ensures all cases covered.
     * LSP guarantee: every subtype MUST implement getMaskedId() without exposing raw data.
     */
    public static String describePayment(PaymentMethod method) {
        return switch (method) {
            case CreditCard c   -> "Credit card ending in " + c.getMaskedId();
            case BankTransfer b -> "Bank transfer from " + b.getMaskedId();
            case CryptoPayment p -> "Crypto wallet " + p.getMaskedId();
            // No default needed — sealed class ensures exhaustive coverage
        };
    }
}

// ================================================================

/**
 * CreditCard is 'final' — it cannot be further extended.
 * getMaskedId() NEVER returns raw PAN data (LSP: upholds the "masked" contract).
 */
public final class CreditCard extends PaymentMethod {
    private final String lastFour;   // Only last 4 digits stored (PCI-DSS)
    private final String hashedPan;  // Full PAN stored only as secure hash

    public CreditCard(String lastFour, String hashedPan) {
        this.lastFour = lastFour;
        this.hashedPan = hashedPan;
    }

    @Override
    public boolean validate() {
        return lastFour != null && lastFour.matches("\\d{4}");
    }

    @Override
    public String getMaskedId() {
        // LSP contract: always masked — never leaks the full PAN
        return "**** **** **** " + lastFour;
    }
}

// ================================================================

public final class BankTransfer extends PaymentMethod {
    private final String routingNumber;  // Not stored raw in real systems
    private final String maskedAccount;  // Pre-masked at ingestion time

    public BankTransfer(String routingNumber, String maskedAccount) {
        this.routingNumber = routingNumber;
        this.maskedAccount = maskedAccount;
    }

    @Override
    public boolean validate() {
        return routingNumber != null && routingNumber.matches("\\d{9}");
    }

    @Override
    public String getMaskedId() {
        return maskedAccount;  // Already masked at creation time
    }
}

// ================================================================

public final class CryptoPayment extends PaymentMethod {
    private final String walletAddress;

    public CryptoPayment(String walletAddress) {
        this.walletAddress = walletAddress;
    }

    @Override
    public boolean validate() {
        // Basic ETH/BTC address format check
        return walletAddress != null && walletAddress.length() >= 26;
    }

    @Override
    public String getMaskedId() {
        if (walletAddress.length() < 10) return "****";
        // Show first 6 + last 4 characters
        return walletAddress.substring(0, 6) + "****" +
               walletAddress.substring(walletAddress.length() - 4);
    }
}

// ================================================================
// What sealed prevents:
//
// class MaliciousPaymentMethod extends PaymentMethod { ... }
//   --> COMPILE ERROR: 'MaliciousPaymentMethod' is not a permitted subclass
//
// This means:
// 1. No deserialization gadget can introduce a new PaymentMethod subtype
// 2. switch statements on PaymentMethod are exhaustive — no unknown cases
// 3. The complete type hierarchy is visible and auditable in one place
