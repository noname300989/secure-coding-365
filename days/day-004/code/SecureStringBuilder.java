import java.util.Objects;

/**
 * Day 4 - Secure String Building patterns
 *
 * Demonstrates: StringBuilder for safe concatenation,
 * input validation, and not logging sensitive data.
 */
public class SecureStringBuilder {

    /**
     * ✅ Builds a SQL-like query string safely.
     *
     * Key security practices:
     * 1. Validate all inputs before use
     * 2. Use StringBuilder (not += in loops)
     * 3. Log count/operation, never log actual data
     * 4. Enforce size limits to prevent DoS
     *
     * NOTE: In real production code, ALWAYS use PreparedStatement
     * with '?' placeholders instead of string-built queries!
     */
    public static String buildSafeUserQuery(int[] userIds) {
        Objects.requireNonNull(userIds, "userIds must not be null");

        if (userIds.length == 0) {
            throw new IllegalArgumentException("userIds must not be empty");
        }
        if (userIds.length > 1000) {
            // Enforce reasonable limit to prevent DoS / oversized queries
            throw new IllegalArgumentException("Too many user IDs: max 1000, got " + userIds.length);
        }

        StringBuilder sb = new StringBuilder("SELECT id, name FROM users WHERE id IN (");
        for (int i = 0; i < userIds.length; i++) {
            if (userIds[i] <= 0) {
                throw new IllegalArgumentException("Invalid user ID at index " + i + ": must be positive");
            }
            sb.append(userIds[i]);
            if (i < userIds.length - 1) {
                sb.append(',');
            }
        }
        sb.append(')');

        // ✅ Log the operation and count — NOT the actual IDs
        System.out.println("Building user query for " + userIds.length + " IDs");

        return sb.toString();
    }

    /**
     * ✅ Builds a display-safe summary string — never include sensitive fields.
     *
     * When building strings for logging or display, explicitly whitelist
     * which fields are safe to include. Never use toString() on objects
     * that might contain passwords, SSNs, credit card numbers, etc.
     */
    public static String buildUserSummary(String username, String role, boolean isActive) {
        Objects.requireNonNull(username, "username must not be null");
        Objects.requireNonNull(role, "role must not be null");

        // ✅ Only include non-sensitive fields
        return new StringBuilder("User[")
                .append("username=").append(sanitizeForLog(username))
                .append(", role=").append(sanitizeForLog(role))
                .append(", active=").append(isActive)
                .append(']')
                .toString();
        // ❌ Never include: password, ssn, creditCard, authToken, etc.
    }

    /**
     * Basic log sanitization — removes newlines to prevent log injection.
     * CWE-117: Improper Output Neutralization for Logs
     */
    private static String sanitizeForLog(String input) {
        if (input == null) return "null";
        // Remove newlines, carriage returns, and null bytes to prevent log injection
        return input.replaceAll("[\r\n\0]", "_");
    }
}
