import java.util.ArrayList;
import java.util.List;

/**
 * VulnerableBankAccount.java
 *
 * ❌ VULNERABLE — DO NOT USE IN PRODUCTION
 *
 * Demonstrates broken encapsulation:
 *   - CWE-668: Exposure of Resource to Wrong Sphere
 *   - CWE-766: Critical Data Element Public Access
 *
 * Problems:
 *   1. Public fields allow direct mutation from any class
 *   2. PIN stored as public String — lives in JVM String pool forever
 *   3. getTransactionHistory() returns the live list — callers can call .clear()
 *   4. setBalance() has no validation — accepts negative, NaN, or Infinity
 *   5. accountNumber exposed in plaintext, no masking
 */
public class VulnerableBankAccount {

    // ❌ PUBLIC fields — anyone can read AND write directly!
    public String accountHolder;
    public double balance;              // can be set to negative by anyone
    public String accountNumber;        // raw sensitive data, no masking
    public String pin;                  // PIN stored as plain String — never do this!
    public boolean isActive = true;
    public List<String> transactionHistory; // external code can call .clear() on this!

    public VulnerableBankAccount(String holder, double initialBalance) {
        this.accountHolder = holder;
        this.balance = initialBalance;
        this.transactionHistory = new ArrayList<>();
    }

    // ❌ No validation — blindly sets whatever value is passed
    public void setBalance(double newBalance) {
        this.balance = newBalance; // attacker can call setBalance(-999999) or setBalance(Double.NaN)
    }

    // ❌ Returns the INTERNAL mutable list — caller can mutate it!
    public List<String> getTransactionHistory() {
        return this.transactionHistory; // dangerous reference escape — caller can call .clear()
    }

    // Demonstration of the vulnerability
    public static void main(String[] args) {
        VulnerableBankAccount account = new VulnerableBankAccount("Alice", 1000.0);
        account.pin = "1234";

        System.out.println("Initial balance: " + account.balance);

        // ❌ Anyone can do this:
        account.balance = -999_999.99; // direct field mutation
        System.out.println("Tampered balance: " + account.balance);

        // ❌ Erase audit trail:
        account.transactionHistory.add("DEPOSIT: +500");
        account.getTransactionHistory().clear(); // erases evidence!
        System.out.println("Transaction history erased: " + account.transactionHistory.isEmpty());

        // ❌ Read raw PIN:
        System.out.println("Stolen PIN: " + account.pin); // "1234"
    }
}
