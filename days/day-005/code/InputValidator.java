// InputValidator.java
// Centralized validation utility — reuse across all service methods
// CWEs addressed: CWE-20 (Improper Input Validation), CWE-117 (Log Injection)

import java.util.regex.Pattern;

public final class InputValidator {

    // Private constructor: utility class, never instantiated
    private InputValidator() {}

    private static final int MAX_USERNAME_LEN = 50;
    private static final int MAX_EMAIL_LEN    = 254; // RFC 5321 limit

    // Allowlist: letters, digits, underscore, hyphen only — kills log injection too
    private static final Pattern USERNAME_PATTERN =
        Pattern.compile("^[a-zA-Z0-9_\\-]+$");

    // Simple email regex (for production use Apache Commons Validator or Jakarta Bean Validation)
    private static final Pattern EMAIL_PATTERN =
        Pattern.compile("^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$");

    /**
     * Ensures a string is non-null and non-blank.
     * @throws IllegalArgumentException if null or blank
     */
    public static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be null or blank");
        }
        return value.trim();
    }

    /**
     * Validates a username against the allowlist pattern and length constraints.
     * Rejects nulls, blanks, HTML tags, newlines, and special characters.
     */
    public static String validateUsername(String username) {
        String cleaned = requireNonBlank(username, "username");
        if (cleaned.length() > MAX_USERNAME_LEN) {
            throw new IllegalArgumentException("username exceeds max length of " + MAX_USERNAME_LEN);
        }
        if (!USERNAME_PATTERN.matcher(cleaned).matches()) {
            throw new IllegalArgumentException(
                "username contains invalid characters (only letters, digits, _ and - allowed)");
        }
        return cleaned;
    }

    /**
     * Validates an email address format and length.
     * Normalizes to lowercase.
     */
    public static String validateEmail(String email) {
        String cleaned = requireNonBlank(email, "email");
        if (cleaned.length() > MAX_EMAIL_LEN) {
            throw new IllegalArgumentException("email exceeds max length of " + MAX_EMAIL_LEN);
        }
        if (!EMAIL_PATTERN.matcher(cleaned).matches()) {
            throw new IllegalArgumentException("invalid email format");
        }
        return cleaned.toLowerCase(); // normalize for consistent storage
    }

    /**
     * Ensures an integer is strictly positive (> 0).
     * Use for amounts, quantities, counts.
     */
    public static int requirePositive(int value, String fieldName) {
        if (value <= 0) {
            throw new IllegalArgumentException(
                fieldName + " must be positive (> 0), got: " + value);
        }
        return value;
    }

    /**
     * Ensures an integer is within [min, max] inclusive.
     * Use for array indices, bounded numeric inputs.
     */
    public static int requireInRange(int value, int min, int max, String fieldName) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(
                fieldName + " must be between " + min + " and " + max + ", got: " + value);
        }
        return value;
    }

    /**
     * Validates a 4-digit PIN string.
     * Exactly 4 characters, all digits.
     */
    public static String validatePin(String pin) {
        requireNonBlank(pin, "pin");
        if (!pin.matches("^\\d{4}$")) {
            throw new IllegalArgumentException("PIN must be exactly 4 digits");
        }
        return pin;
    }
}
