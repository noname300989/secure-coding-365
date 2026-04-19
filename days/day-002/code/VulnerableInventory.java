// VULNERABLE: Autoboxing null + type confusion
// CWE-476: NULL Pointer Dereference
// CWE-704: Incorrect Type Conversion or Cast
import java.util.HashMap;
import java.util.Map;

public class VulnerableInventory {

    private Map<String, Integer> stockLevels = new HashMap<>();

    public void processOrder(String item, int quantity) {
        // DANGEROUS: if item not in map, get() returns null
        // Unboxing null Integer to int throws NullPointerException!
        int currentStock = stockLevels.get(item); // 💥 NullPointerException!

        if (currentStock >= quantity) {
            stockLevels.put(item, currentStock - quantity);
        }
    }

    // ALSO DANGEROUS: Comparing with == instead of .equals()
    public boolean hasUnlimitedStock(String item) {
        Integer stock = stockLevels.get(item);

        // == compares object references, not values!
        // Only reliable for -128 to 127 (Integer cache range)
        // For values outside that range, this RANDOMLY returns false!
        return stock == 1000; // 💣 Type confusion bug!
    }

    // DANGEROUS: Implicit narrowing cast
    public byte getByteCount(int total) {
        return (byte) total; // Silently truncates if total > 127!
        // e.g., total=300 becomes 44 (300 - 256 = 44)
    }
}
