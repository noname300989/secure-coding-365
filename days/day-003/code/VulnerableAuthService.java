/**
 * VULNERABLE: AuthService.java
 * 
 * Demonstrates common control flow security vulnerabilities in Java:
 * - CWE-697: Incorrect Comparison (== for Strings)
 * - CWE-1254: Logic error allowing null bypass
 * - CWE-208: Timing-unsafe secret comparison
 * - Switch fall-through privilege escalation
 * 
 * DO NOT USE IN PRODUCTION.
 */
public class VulnerableAuthService {

    // ===== BUG 1: Using == for String comparison (CWE-697) =====
    // == checks object identity, not value equality.
    // Works by accident with compile-time String literals (interned),
    // but FAILS for runtime Strings (e.g., from HTTP request params).
    public boolean isAdmin(String role) {
        return role == "admin";  // ❌ WRONG: identity check, not equality
    }

    // ===== BUG 2: Null bypass via || short-circuit (CWE-1254) =====
    // If user is null, the first condition is TRUE.
    // Due to || short-circuit, user.getRole() is never called.
    // BUT the whole expression is true — null user gets access!
    // Also: if user is not null but getRole() throws NPE, it propagates.
    public boolean canAccessResource(User user, String requiredRole) {
        if (user == null || user.getRole().equals(requiredRole)) {
            return true;  // ❌ null user passes through!
        }
        return false;
    }

    // ===== BUG 3: Off-by-one loop boundary (ArrayIndexOutOfBoundsException) =====
    // i <= allowedRoles.length means the last iteration accesses
    // allowedRoles[allowedRoles.length] which is out of bounds.
    public boolean checkPermissions(String[] allowedRoles, String userRole) {
        for (int i = 0; i <= allowedRoles.length; i++) {  // ❌ <= should be <
            if (allowedRoles[i].equals(userRole)) {         // crashes on last iter
                return true;
            }
        }
        return false;
    }

    // ===== BUG 4: Short-circuit skips mandatory security function =====
    // If isAuthenticated() returns true, logAccess() is NEVER called.
    // The audit trail silently disappears for authenticated users —
    // the ones you most want to track!
    public boolean processRequest(Request req) {
        if (isAuthenticated(req) || logAccess(req)) {  // ❌ logAccess skipped!
            return handleRequest(req);
        }
        return false;
    }

    // ===== BUG 5: Switch fall-through privilege escalation =====
    // Missing break causes "guest" to get access level 5 (moderator)!
    // Java compiles this without any warning.
    public int getAccessLevel(String role) {
        int level = 0;
        switch (role) {
            case "guest":
                level = 1;
                // ❌ MISSING break! Falls through to "user"
            case "user":
                level = 2;
                // ❌ MISSING break! Falls through to "moderator"
            case "moderator":
                level = 5;
                break;
            case "admin":
                level = 10;
                break;
            default:
                level = 0;
        }
        // A guest asking for level 1 gets level 5 (moderator)!
        return level;
    }

    // ===== BUG 6: Timing-unsafe secret comparison (CWE-208) =====
    // String.equals() short-circuits at the FIRST character mismatch.
    // Response time varies based on how many chars match at the start.
    // Attacker can measure nanosecond differences to extract secret char by char.
    // Converts O(62^32) brute force into O(62×32) incremental attack.
    public boolean verifyApiKey(String providedKey, String storedKey) {
        return providedKey.equals(storedKey);  // ❌ timing leak!
    }

    // Placeholder method stubs (not meant to run)
    private boolean isAuthenticated(Object req) { return true; }
    private boolean logAccess(Object req) { return true; }
    private boolean handleRequest(Object req) { return true; }
    static class Request {}
    static class User { public String getRole() { return "user"; } }
}
