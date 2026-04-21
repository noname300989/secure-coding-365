// BankAccountChallenge.java
// 🏋️ Mini Challenge — Day 5: Methods & Input Validation
//
// Task: Implement the withdraw() and setOwnerName() methods securely.
//
// Requirements:
//   - accountId: alphanumeric, 8-16 chars
//   - ownerName: letters and spaces only, 2-100 chars
//   - pin: exactly 4 digits ("0000"-"9999")
//   - withdrawal amount: positive, <= current balance, <= 10000.0 (daily limit)
//   - Return the new balance after withdrawal
//   - Log a sanitized audit message (no PIN, no full balance in production)
//   - Throw descriptive exceptions for all invalid inputs

import java.util.logging.*;
import java.util.regex.Pattern;

public class BankAccountChallenge {

    private static final Logger LOG = Logger.getLogger(BankAccountChallenge.class.getName());

    private final String accountId;
    private String ownerName;
    private double balance;

    private static final double DAILY_WITHDRAWAL_LIMIT = 10_000.0;

    // Valid accountId: alphanumeric, 8-16 characters
    private static final Pattern ACCOUNT_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9]{8,16}$");
    // Valid ownerName: letters and spaces only, 2-100 chars
    private static final Pattern OWNER_NAME_PATTERN  = Pattern.compile("^[a-zA-Z ]{2,100}$");

    public BankAccountChallenge(String accountId, String ownerName, double initialBalance) {
        if (accountId == null || !ACCOUNT_ID_PATTERN.matcher(accountId).matches()) {
            throw new IllegalArgumentException("Invalid accountId (must be 8-16 alphanumeric chars)");
        }
        this.accountId = accountId;
        setOwnerName(ownerName);
        if (initialBalance < 0) {
            throw new IllegalArgumentException("Initial balance cannot be negative");
        }
        this.balance = initialBalance;
    }

    /**
     * Sets/updates the account owner's name.
     * Allowed: letters and spaces only, 2-100 chars (trimmed).
     *
     * @param name the new owner name
     * @throws IllegalArgumentException if name is null, blank, or contains invalid characters
     */
    public void setOwnerName(String name) {
        // TODO: Implement validation here
        // 1. Reject null/blank
        // 2. Trim whitespace
        // 3. Validate against OWNER_NAME_PATTERN
        // 4. Assign to this.ownerName
        throw new UnsupportedOperationException("TODO: implement setOwnerName()");
    }

    /**
     * Withdraws money from this account.
     *
     * @param amount the amount to withdraw (must be > 0, <= balance, <= DAILY_WITHDRAWAL_LIMIT)
     * @param pin    a 4-digit PIN string
     * @return the remaining balance after withdrawal
     * @throws IllegalArgumentException if pin format is invalid or amount is out of range
     * @throws IllegalStateException    if insufficient funds
     */
    public double withdraw(double amount, String pin) {
        // TODO: Implement securely:
        // 1. Validate pin using InputValidator.validatePin()
        // 2. Validate amount > 0
        // 3. Validate amount <= DAILY_WITHDRAWAL_LIMIT
        // 4. Check amount <= balance (insufficient funds)
        // 5. Deduct amount from balance
        // 6. Log: "Withdrawal from account [accountId]: status=success" (no amount, no pin)
        // 7. Return new balance
        throw new UnsupportedOperationException("TODO: implement withdraw()");
    }

    // Getters
    public String getAccountId() { return accountId; }
    public String getOwnerName()  { return ownerName; }
    public double getBalance()    { return balance; }

    // -------------------------
    // Sample test runner
    // -------------------------
    public static void main(String[] args) {
        System.out.println("=== BankAccountChallenge Tests ===\n");

        BankAccountChallenge account = new BankAccountChallenge("ACC00001", "Alice Smith", 5000.0);

        // Test 1: Valid withdrawal
        try {
            double remaining = account.withdraw(200.0, "1234");
            System.out.println("✅ Test 1 passed — balance after $200 withdrawal: " + remaining);
        } catch (Exception e) {
            System.out.println("❌ Test 1 failed: " + e.getMessage());
        }

        // Test 2: Invalid PIN (not 4 digits)
        try {
            account.withdraw(100.0, "12x4");
            System.out.println("❌ Test 2 failed — should have rejected invalid PIN");
        } catch (IllegalArgumentException e) {
            System.out.println("✅ Test 2 passed — invalid PIN rejected: " + e.getMessage());
        }

        // Test 3: Negative amount
        try {
            account.withdraw(-500.0, "1234");
            System.out.println("❌ Test 3 failed — should have rejected negative amount");
        } catch (IllegalArgumentException e) {
            System.out.println("✅ Test 3 passed — negative amount rejected: " + e.getMessage());
        }

        // Test 4: Amount exceeds daily limit
        try {
            account.withdraw(15_000.0, "1234");
            System.out.println("❌ Test 4 failed — should have rejected amount > daily limit");
        } catch (IllegalArgumentException e) {
            System.out.println("✅ Test 4 passed — daily limit enforced: " + e.getMessage());
        }

        // Test 5: Insufficient funds
        try {
            account.withdraw(9_000.0, "1234"); // more than current balance
            System.out.println("❌ Test 5 failed — should have detected insufficient funds");
        } catch (IllegalStateException e) {
            System.out.println("✅ Test 5 passed — insufficient funds detected: " + e.getMessage());
        }

        // Test 6: Invalid owner name (contains digits)
        try {
            account.setOwnerName("Alice123");
            System.out.println("❌ Test 6 failed — should have rejected name with digits");
        } catch (IllegalArgumentException e) {
            System.out.println("✅ Test 6 passed — invalid name rejected: " + e.getMessage());
        }

        System.out.println("\nAll tests complete. Implement the TODOs to make them pass!");
    }
}
