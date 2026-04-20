import java.util.Arrays;

/**
 * Day 4 - SECURE code examples for Arrays & Strings
 *
 * Demonstrates secure patterns for:
 * - Array bounds validation (CWE-129 prevention)
 * - char[] for password handling (CWE-256 prevention)
 * - Constant-time comparison (timing attack prevention)
 * - Safe error messages (CWE-209 prevention)
 * - Correct loop boundaries (CWE-193 prevention)
 */
public class SecureStringArrayHandler {

    // ✅ FIX 1: Always validate array index before use
    // Check BOTH: index >= 0 (no negative) AND index < length (no overflow)
    public static String getPermissionByIndex(String[] permissions, int index) {
        if (permissions == null || index < 0 || index >= permissions.length) {
            // Generic message — does NOT reveal array size or contents
            throw new IllegalArgumentException("Invalid permission index");
        }
        return permissions[index];
    }

    // ✅ FIX 2: Use char[] for passwords — can be zeroed from memory
    // Java's JPasswordField.getPassword() also returns char[] for this reason
    public static boolean authenticateUser(String username, char[] inputPassword) {
        char[] storedPassword = getPasswordFromDB(username);
        try {
            return constantTimeCharArrayEquals(storedPassword, inputPassword);
        } finally {
            // Zero out sensitive data IMMEDIATELY after use, success or failure
            // This overwrites the heap memory before GC can move it
            Arrays.fill(storedPassword, '\0');
            // Note: caller should also zero inputPassword after this call
        }
    }

    /**
     * Constant-time char array comparison.
     *
     * Standard equals() or Arrays.equals() stops at the first mismatch —
     * a timing side-channel. An attacker can measure response times to
     * determine how many leading characters of their guess are correct.
     *
     * This implementation always runs all iterations regardless of mismatches.
     * XOR of equal chars = 0; XOR of different chars = non-zero.
     * OR-ing all differences: result is 0 only if ALL chars matched.
     */
    private static boolean constantTimeCharArrayEquals(char[] a, char[] b) {
        if (a.length != b.length) {
            return false; // Length check doesn't leak content
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    // ✅ FIX 4: Correct off-by-one + safe error message
    public static void processRoles(String[] roles) {
        if (roles == null || roles.length == 0) {
            throw new IllegalArgumentException("Roles array must not be null or empty");
        }
        for (int i = 0; i < roles.length; i++) { // ✅ < not <=
            if (roles[i] == null || roles[i].isBlank()) {
                throw new IllegalArgumentException("Invalid role at index " + i);
            }
            System.out.println("Processing: " + roles[i]);
        }
    }

    private static char[] getPasswordFromDB(String username) {
        return "SuperSecret123".toCharArray(); // Simulated
    }

    // ✅ Demonstration of clearing sensitive data
    public static void demonstrateClearingMemory() {
        char[] password = "MySecretPassword!".toCharArray();

        try {
            // ... use password for authentication ...
            System.out.println("Authentication complete");
        } finally {
            // Zero out — overwrites memory immediately
            Arrays.fill(password, '\0');
            System.out.println("Password cleared from memory");
        }
        // At this point, the char[] on heap contains all '\0' — not the password
    }
}
