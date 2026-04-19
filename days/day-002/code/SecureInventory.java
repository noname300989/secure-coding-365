// SECURE: Null-safe autoboxing and correct type comparison
// Demonstrates: getOrDefault, .equals(), Optional, safe narrowing cast
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SecureInventory {

    private Map<String, Integer> stockLevels = new HashMap<>();

    // SAFE: Use getOrDefault() to avoid null unboxing
    public void processOrder(String item, int quantity) {
        if (item == null || item.isBlank()) {
            throw new IllegalArgumentException("Item name cannot be null/blank");
        }
        if (quantity <= 0) {
            throw new IllegalArgumentException("Quantity must be positive");
        }

        // getOrDefault avoids NullPointerException from null unboxing
        int currentStock = stockLevels.getOrDefault(item, 0);

        if (currentStock < quantity) {
            throw new IllegalStateException(
                "Insufficient stock for: " + item);
        }

        stockLevels.put(item, currentStock - quantity);
    }

    // SAFE: Use .equals() for Integer comparison, not ==
    public boolean hasUnlimitedStock(String item) {
        Integer stock = stockLevels.get(item);
        if (stock == null) return false;

        return stock.equals(1000); // .equals() compares VALUE, not reference
        // OR: Integer.valueOf(1000).equals(stock)
    }

    // SAFE: Optional-based approach for nullable returns
    public Optional<Integer> getStock(String item) {
        return Optional.ofNullable(stockLevels.get(item));
    }

    // SAFE: Explicit range check before narrowing cast
    public byte getByteCount(int total) {
        if (total < Byte.MIN_VALUE || total > Byte.MAX_VALUE) {
            throw new ArithmeticException(
                "Value " + total + " out of byte range [" +
                Byte.MIN_VALUE + ", " + Byte.MAX_VALUE + "]");
        }
        return (byte) total; // Now safe: range validated before cast
    }

    // BONUS: Safe int-to-long widening (always safe in Java)
    public long getTotalValueCents(int pricePerUnit, int units) {
        // Multiply as long to prevent int overflow before widening!
        return (long) pricePerUnit * units; // Cast BEFORE multiply!
        // NOT: (long)(pricePerUnit * units) — overflow happens FIRST, then cast
    }

    public static void main(String[] args) {
        SecureInventory inv = new SecureInventory();
        inv.stockLevels.put("widget", 50);

        // Safe order processing
        inv.processOrder("widget", 10);
        System.out.println("Order processed: " +
            inv.getStock("widget").orElse(0) + " left");

        // Safe byte range check
        try {
            byte b = inv.getByteCount(300);
        } catch (ArithmeticException e) {
            System.out.println("Caught: " + e.getMessage());
        }

        // Safe long multiplication
        int price = 50000; // $500.00 in cents
        int qty = 100000;
        System.out.println("Total: $" +
            inv.getTotalValueCents(price, qty) / 100.0);
    }
}
