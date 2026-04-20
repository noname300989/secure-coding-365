import java.util.Arrays;

/**
 * Day 4 - Mini Challenge: Secure PIN Verification
 *
 * Your task: Rewrite verifyPINSecure() to:
 * 1. Accept char[] instead of String for the input PIN
 * 2. Implement constant-time comparison (no String.equals() or Arrays.equals())
 * 3. Zero out the input char array in a finally block
 * 4. Add input validation: null check, length == 4, digits only
 * 5. Return a generic error message that doesn't reveal which check failed
 *
 * BONUS: What would change if the stored PIN were a bcrypt hash?
 */
public class PINVerifierChallenge {

    // ❌ Broken implementation — do NOT use in production
    public static boolean verifyPIN(String inputPIN, String storedPIN) {
        return storedPIN.equals(inputPIN);
        // Issues: String can't be zeroed, equals() is not constant-time
    }

    // ✅ Your job: implement this securely
    public static boolean verifyPINSecure(char[] inputPIN, char[] storedPIN) {
        // TODO 1: Validate inputPIN is not null
        // TODO 2: Validate inputPIN.length == 4
        // TODO 3: Validate all characters in inputPIN are digits ('0'-'9')
        // TODO 4: Implement constant-time comparison using XOR
        // TODO 5: Zero out inputPIN in a finally block

        return false; // Replace with your implementation
    }

    // ----------- SOLUTION (uncomment to check your work) -----------
    /*
    public static boolean verifyPINSecureSolution(char[] inputPIN, char[] storedPIN) {
        if (inputPIN == null) {
            throw new IllegalArgumentException("Invalid PIN");
        }
        if (inputPIN.length != 4) {
            throw new IllegalArgumentException("Invalid PIN");
        }
        for (char c : inputPIN) {
            if (c < '0' || c > '9') {
                throw new IllegalArgumentException("Invalid PIN");
            }
        }

        try {
            if (storedPIN == null || storedPIN.length != 4) {
                return false; // Internal error — stored PIN malformed
            }
            int diff = 0;
            for (int i = 0; i < 4; i++) {
                diff |= (inputPIN[i] ^ storedPIN[i]);
            }
            return diff == 0;
        } finally {
            Arrays.fill(inputPIN, '\0');
        }
    }
    */
    // BONUS answer: With bcrypt, you'd pass inputPIN to BCrypt.checkpw(new String(inputPIN), storedHash)
    // BUT you must convert to String only momentarily and use a bcrypt lib that handles timing safely.
    // Argon2 or bcrypt's checkpw() are already constant-time internally.
}
