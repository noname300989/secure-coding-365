/**
 * SECURE: AuthService.java
 * 
 * Demonstrates secure control flow patterns in Java:
 * - Proper String comparison with .equals() and Yoda conditions
 * - Explicit null guard before field access
 * - Correct loop boundaries
 * - Decoupled security-critical function calls
 * - Switch with return (no fall-through possible)
 * 
 * CWEs Addressed: CWE-697, CWE-1254, CWE-208
 */
public class SecureAuthService {

    // ===== FIX 1: Use .equals() with Yoda condition =====
    // "admin".equals(role) is safe even if role is null (returns false, no NPE).
    // Yoda condition puts the constant on the left.
    public boolean isAdmin(String role) {
        return "admin".equals(role);  // ✅ value equality, null-safe
    }

    // ===== FIX 2: Explicit null check before field access =====
    // Check each parameter explicitly before using it.
    // Deny access for any unexpected null value.
    public boolean canAccessResource(User user, String requiredRole) {
        if (user == null) {
            return false;  // ✅ reject null users explicitly
        }
        if (requiredRole == null) {
            return false;  // ✅ reject null roles too
        }
        return requiredRole.equals(user.getRole());  // ✅ safe to call getRole()
    }

    // ===== FIX 3: Correct loop boundary + null guard =====
    // Use < (strict less than) for array index bounds.
    // Also: consider using List/Set for this type of containment check.
    public boolean checkPermissions(String[] allowedRoles, String userRole) {
        if (allowedRoles == null || userRole == null) {
            return false;
        }
        for (int i = 0; i < allowedRoles.length; i++) {  // ✅ strict <
            if (userRole.equals(allowedRoles[i])) {
                return true;
            }
        }
        // Better alternative: Arrays.asList(allowedRoles).contains(userRole)
        return false;
    }

    // ===== FIX 4: Decouple mandatory security calls =====
    // Execute security-critical functions unconditionally.
    // Only use their results in the authorization decision.
    public boolean processRequest(Request req) {
        boolean authenticated = isAuthenticated(req);
        boolean logged = logAccess(req);  // ✅ always called, never skipped

        if (!logged) {
            // Fail closed: if audit logging fails, reject the request.
            // You can't have a security system without an audit trail.
            throw new SecurityException("Audit log failure — request rejected for safety");
        }

        return authenticated && handleRequest(req);
    }

    // ===== FIX 5: Switch with return — no fall-through possible =====
    // Each case uses return, which immediately exits the method.
    // Fall-through is physically impossible with return statements.
    public int getAccessLevel(String role) {
        if (role == null) return 0;

        switch (role) {
            case "guest":     return 1;  // ✅ return exits immediately
            case "user":      return 2;
            case "moderator": return 5;
            case "admin":     return 10;
            default:          return 0;  // ✅ unknown roles get zero access
        }
    }

    // Placeholder method stubs (not meant to run)
    private boolean isAuthenticated(Object req) { return true; }
    private boolean logAccess(Object req) { return true; }
    private boolean handleRequest(Object req) { return true; }
    static class Request {}
    static class User { public String getRole() { return "user"; } }
}
