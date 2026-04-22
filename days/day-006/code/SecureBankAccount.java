import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * SecureBankAccount.java
 *
 * ✅ SECURE — Demonstrates proper encapsulation in Java
 *
 * Security features:
 *   - All fields private; identity fields are final
 *   - char[] for PIN storage (can be zeroed after use)
 *   - Defensive copies returned from getters (immutable views)
 *   - All mutations via validated business methods
 *   - final class prevents subclass override of security logic
 *   - Account number only exposed in masked form
 */
public final class SecureBankAccount {

    // ✅ ALL fields are private
    private final String accountHolder;    // final → immutable after construction
    private final String accountNumber;    // never expose raw value
    private double balance;
    private char[] pin;                    // char[] instead of String (can be wiped!)
    private final List<String> transactionHistory;
    private boolean isActive;

    public SecureBankAccount(String holder, String accountNumber,
                             double initialBalance, char[] pin) {
        // ✅ Validate ALL inputs in the constructor
        if (holder == null || holder.isBlank())
            throw new IllegalArgumentException("Account holder name is required");
        if (!isValidAccountNumber(accountNumber))
            throw new IllegalArgumentException("Invalid account number format (12-16 digits required)");
        if (initialBalance < 0)
            throw new IllegalArgumentException("Initial balance cannot be negative");
        if (pin == null || pin.length < 4)
            throw new IllegalArgumentException("PIN must be at least 4 digits");

        this.accountHolder = holder;
        this.accountNumber = accountNumber;
        this.balance = initialBalance;
        // ✅ Store a DEFENSIVE COPY of pin, not the caller's array
        this.pin = Arrays.copyOf(pin, pin.length);
        this.transactionHistory = new ArrayList<>();
        this.isActive = true;
    }

    // ✅ Read-only access with masking — raw account number is never exposed
    public String getMaskedAccountNumber() {
        return "****-****-" + accountNumber.substring(accountNumber.length() - 4);
    }

    public String getAccountHolder() { return accountHolder; } // String is immutable — safe
    public double getBalance()       { return balance; }       // primitive copy — safe
    public boolean isActive()        { return isActive; }

    // ✅ Business logic lives inside the class — balance can't be set from outside
    public void deposit(double amount) {
        if (!isActive) throw new IllegalStateException("Account is not active");
        if (amount <= 0 || Double.isNaN(amount) || Double.isInfinite(amount))
            throw new IllegalArgumentException("Deposit must be a positive finite number");
        balance += amount;
        transactionHistory.add(String.format("DEPOSIT: +%.2f (balance: %.2f)", amount, balance));
    }

    public void withdraw(double amount) {
        if (!isActive) throw new IllegalStateException("Account is not active");
        if (amount <= 0 || Double.isNaN(amount) || Double.isInfinite(amount))
            throw new IllegalArgumentException("Amount must be a positive finite number");
        if (amount > balance)
            throw new IllegalArgumentException("Insufficient funds");
        balance -= amount;
        transactionHistory.add(String.format("WITHDRAWAL: -%.2f (balance: %.2f)", amount, balance));
    }

    // ✅ Defensive copy — caller gets an unmodifiable snapshot, not the live list
    public List<String> getTransactionHistory() {
        return Collections.unmodifiableList(new ArrayList<>(transactionHistory));
    }

    // ✅ Verify PIN without exposing its contents
    public boolean verifyPin(char[] inputPin) {
        if (inputPin == null || inputPin.length != pin.length) return false;
        // Constant-time comparison to prevent timing attacks
        int diff = 0;
        for (int i = 0; i < pin.length; i++) {
            diff |= (pin[i] ^ inputPin[i]);
        }
        return diff == 0;
    }

    // ✅ Zero out sensitive data when account is closed
    public void close() {
        isActive = false;
        Arrays.fill(pin, '\0'); // wipe PIN from memory immediately
        pin = new char[0];
        transactionHistory.add("ACCOUNT CLOSED");
    }

    private static boolean isValidAccountNumber(String acct) {
        return acct != null && Pattern.matches("[0-9]{12,16}", acct);
    }

    // ✅ Safe toString — never exposes sensitive fields
    @Override
    public String toString() {
        return String.format("BankAccount{holder='%s', account='%s', balance=%.2f, active=%b}",
                accountHolder, getMaskedAccountNumber(), balance, isActive);
    }

    // Demonstration of the secure design
    public static void main(String[] args) {
        SecureBankAccount account = new SecureBankAccount(
                "Alice", "123456789012", 1000.0, "1234".toCharArray());

        System.out.println(account);

        account.deposit(500.0);
        account.withdraw(200.0);

        System.out.println("Balance: " + account.getBalance());
        System.out.println("Account: " + account.getMaskedAccountNumber());

        // ✅ Can't modify the returned list
        List<String> history = account.getTransactionHistory();
        try {
            history.add("FAKE ENTRY"); // throws UnsupportedOperationException
        } catch (UnsupportedOperationException e) {
            System.out.println("Cannot tamper with transaction history: " + e.getClass().getSimpleName());
        }

        // ✅ PIN verification without exposure
        System.out.println("PIN correct: " + account.verifyPin("1234".toCharArray()));
        System.out.println("PIN wrong:   " + account.verifyPin("9999".toCharArray()));

        account.close();
        System.out.println("After close: " + account);
    }
}
