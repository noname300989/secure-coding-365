// VULNERABLE: Integer overflow in account balance calculation
// CWE-190: Integer Overflow or Wraparound
public class VulnerableBank {

    // MAX int value: 2,147,483,647
    private int balance = 2_000_000_000; // $2 billion (near int max)

    public void deposit(int amount) {
        // No overflow check!
        balance += amount; // DANGER: can wrap to negative!
        System.out.println("New balance: $" + balance);
    }

    public boolean canWithdraw(int amount) {
        // If balance overflowed to negative, this check is useless
        return balance >= amount;
    }

    public static void main(String[] args) {
        VulnerableBank bank = new VulnerableBank();
        bank.deposit(200_000_000); // Add $200 million
        // Result: balance = 2,000,000,000 + 200,000,000
        //       = 2,200,000,000 which EXCEEDS Integer.MAX_VALUE (2,147,483,647)
        //       = WRAPS to -2,094,967,296 (a NEGATIVE balance!)
        System.out.println("Can withdraw $1? " + bank.canWithdraw(1));
        // Output: Can withdraw $1? false (victim has -$2B now!)
    }
}
