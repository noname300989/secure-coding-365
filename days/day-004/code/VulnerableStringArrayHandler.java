import java.util.Arrays;

/**
 * Day 4 - VULNERABLE code examples for Arrays & Strings
 * 
 * DO NOT use these patterns in production code.
 * These demonstrate common security mistakes.
 * 
 * CWEs: CWE-125, CWE-129, CWE-193, CWE-209, CWE-256
 */
public class VulnerableStringArrayHandler {

    // ❌ VULNERABILITY 1: No bounds checking on user-supplied index
    // CWE-129: Improper Validation of Array Index
    // Attacker sends index=-1, Integer.MAX_VALUE, or array.length
    // → Throws ArrayIndexOutOfBoundsException with stack trace leak
    public static String getPermissionByIndex(String[] permissions, int index) {
        return permissions[index]; // Direct access — UNSAFE
    }

    // ❌ VULNERABILITY 2: Password stored as String
    // CWE-256: Plaintext Storage of Password
    // Problems:
    //   1. Both passwords sit on the heap as String objects
    //   2. String.equals() is NOT constant-time (enables timing attacks)
    //   3. Neither can be zeroed — persist until GC, may be in heap dumps
    public static boolean authenticateUser(String username, String inputPassword) {
        String storedPassword = getPasswordFromDB(username); // Returns String!
        return storedPassword.equals(inputPassword);
    }

    // ❌ VULNERABILITY 3: Concatenating sensitive data + logging it
    // CWE-209: Information Exposure Through Error Message
    // String concatenation in loop + logging query content
    public static String buildUserQuery(String[] userIds) {
        String query = "SELECT * FROM users WHERE id IN (";
        for (String id : userIds) {
            query += id + ","; // String concatenation in loop — also logs all IDs
        }
        query += ")";
        System.out.println("Executing: " + query); // ❌ Logs all user IDs!
        return query;
    }

    // ❌ VULNERABILITY 4: Off-by-one error + revealing error message
    // CWE-193: Off-by-One Error
    // i <= roles.length should be i < roles.length
    public static void processRoles(String[] roles) {
        try {
            for (int i = 0; i <= roles.length; i++) { // Bug: <= causes out-of-bounds
                System.out.println("Processing: " + roles[i]);
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            // ❌ Leaks full array contents!
            throw new RuntimeException("Error processing roles: " + Arrays.toString(roles), e);
        }
    }

    private static String getPasswordFromDB(String username) {
        return "SuperSecret123"; // Simulated DB fetch
    }
}
