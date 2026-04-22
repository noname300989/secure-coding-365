/**
 * ImmutableMoney.java
 *
 * ✅ SECURE — A truly immutable value object for currency amounts.
 *
 * Key properties:
 *   - final class: cannot be subclassed to introduce mutability
 *   - All fields final: state cannot change after construction
 *   - Operations return NEW objects, never mutate 'this'
 *   - Uses long cents (not double) to avoid floating-point arithmetic bugs
 *   - Validates ISO 4217 currency codes
 *
 * Thread-safe by design: immutable objects can be shared freely
 * across threads without synchronization.
 *
 * Why NOT double for money?
 *   double x = 0.1 + 0.2;   // x = 0.30000000000000004  ← real bug in financial systems!
 *   Use long cents or BigDecimal instead.
 */
public final class ImmutableMoney {

    private final long amountInCents;   // e.g. $19.99 = 1999
    private final String currency;      // ISO 4217: "USD", "EUR", "INR", etc.

    public ImmutableMoney(long amountInCents, String currency) {
        if (amountInCents < 0)
            throw new IllegalArgumentException("Amount cannot be negative: " + amountInCents);
        if (currency == null || !currency.matches("[A-Z]{3}"))
            throw new IllegalArgumentException("Invalid ISO 4217 currency code: " + currency);
        this.amountInCents = amountInCents;
        this.currency = currency;
    }

    public long getAmountInCents() { return amountInCents; }
    public String getCurrency()    { return currency; }

    /**
     * Returns a NEW ImmutableMoney representing the sum.
     * This object is unchanged — immutability preserved.
     */
    public ImmutableMoney add(ImmutableMoney other) {
        if (!this.currency.equals(other.currency))
            throw new IllegalArgumentException(
                    "Currency mismatch: " + this.currency + " vs " + other.currency);
        return new ImmutableMoney(this.amountInCents + other.amountInCents, this.currency);
    }

    /**
     * Returns a NEW ImmutableMoney representing the difference.
     * Throws if result would be negative.
     */
    public ImmutableMoney subtract(ImmutableMoney other) {
        if (!this.currency.equals(other.currency))
            throw new IllegalArgumentException("Currency mismatch");
        if (other.amountInCents > this.amountInCents)
            throw new IllegalArgumentException("Result would be negative");
        return new ImmutableMoney(this.amountInCents - other.amountInCents, this.currency);
    }

    @Override
    public String toString() {
        return String.format("%s %.2f", currency, amountInCents / 100.0);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ImmutableMoney)) return false;
        ImmutableMoney other = (ImmutableMoney) o;
        return amountInCents == other.amountInCents && currency.equals(other.currency);
    }

    @Override
    public int hashCode() {
        return 31 * Long.hashCode(amountInCents) + currency.hashCode();
    }

    public static void main(String[] args) {
        ImmutableMoney price = new ImmutableMoney(1999, "USD"); // $19.99
        ImmutableMoney tax   = new ImmutableMoney(160, "USD");  // $1.60
        ImmutableMoney total = price.add(tax);                  // $21.59

        // price and tax are UNCHANGED — immutability in action
        System.out.println("Price:  " + price);   // USD 19.99
        System.out.println("Tax:    " + tax);      // USD 1.60
        System.out.println("Total:  " + total);    // USD 21.59
        System.out.println("Price unchanged: " + price.equals(new ImmutableMoney(1999, "USD"))); // true

        // Floating-point bug demonstration — why we use long cents:
        double a = 0.1 + 0.2;
        System.out.println("0.1 + 0.2 (double) = " + a);       // 0.30000000000000004 ← BUG
        ImmutableMoney m1 = new ImmutableMoney(10, "USD");       // $0.10
        ImmutableMoney m2 = new ImmutableMoney(20, "USD");       // $0.20
        System.out.println("0.10 + 0.20 (ImmutableMoney) = " + m1.add(m2)); // USD 0.30 ✓
    }
}
