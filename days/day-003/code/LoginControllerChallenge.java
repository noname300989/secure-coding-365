/**
 * CHALLENGE: LoginControllerChallenge.java
 * 
 * This class has MULTIPLE security bugs. Find them all and write the fixed version!
 * 
 * Bugs to find (don't peek until you've tried!):
 * 1. Switch fall-through (intentional or accidental? Does it need documentation?)
 * 2. Logic inversion: a null user passes through when it should be rejected
 * 3. Plaintext password comparison (should use hash comparison)
 * 4. NullPointerException if the X-Admin-Token header is absent
 * 5. Timing-unsafe token comparison (use MessageDigest.isEqual() instead)
 * 
 * YOUR TASK: Write LoginControllerFixed.java with all bugs corrected.
 */
public class LoginControllerChallenge {

    private static final String ADMIN_TOKEN = "SecretAdminToken2026";

    public boolean login(String username, String password, String role) {

        // === Step 1: Determine if admin role ===
        boolean isAdmin = false;
        switch (role) {
            case "superadmin":
                isAdmin = true;
                // BUG 1: Is this fall-through intentional?
                // If superadmin should ALSO get isAdmin=true via the admin case,
                // it's redundant but harmless. But is it documented? What if someone
                // adds code between the cases later?
            case "admin":
                isAdmin = true;
                break;
            default:
                isAdmin = false;
        }

        // === Step 2: Validate credentials ===
        User user = userRepo.findByUsername(username);
        // BUG 2: Logic inversion!
        // This condition is TRUE when user is null OR password matches.
        // Intent was probably: reject if user is null OR password doesn't match.
        // As written: null user returns false (rejected), but a matching password
        // on a valid user also returns false (also rejected!) — inverted logic.
        // AND: if user is not null but getPassword() throws, it propagates.
        if (user == null || user.getPassword().equals(password)) {
            return false;
        }
        // BUG 3: Even if the logic were correct, comparing raw passwords is wrong.
        // Passwords must be stored as hashes (BCrypt/Argon2) and compared with
        // the hashing library's verify function.

        // === Step 3: Verify admin token ===
        String headerToken = getRequestHeader("X-Admin-Token");
        // BUG 4: If the header is absent, headerToken is null.
        // Calling null.equals(...) throws NullPointerException!
        // BUG 5: Even if null is handled, .equals() is timing-unsafe for tokens.
        if (isAdmin && headerToken.equals(ADMIN_TOKEN)) {
            grantAdminAccess();
        }

        return true;
    }

    // Stub methods — don't modify
    private UserRepository userRepo = new UserRepository();
    private String getRequestHeader(String name) { return null; }
    private void grantAdminAccess() {}

    static class User {
        public String getPassword() { return "password123"; }
    }

    static class UserRepository {
        public User findByUsername(String username) { return null; }
    }
}
