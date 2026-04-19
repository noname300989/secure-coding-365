import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/**
 * SECURE: SecureComparison.java
 * 
 * Timing-safe string comparison utility.
 * 
 * Addresses CWE-208: Observable Timing Discrepancy
 * 
 * Why MessageDigest.isEqual() is safe:
 * - It XORs every byte of both arrays and accumulates the result
 * - The loop ALWAYS runs the full length of both arrays
 * - No early return on mismatch — timing is constant regardless of content
 * - JDK contract guarantees constant-time behavior
 * 
 * When to use this:
 * - API key comparison
 * - CSRF token validation
 * - HMAC signature verification
 * - Session token comparison
 * - Any secret value comparison where timing side-channels matter
 * 
 * When NOT to use this (use proper password hashing instead):
 * - Password comparison → use BCrypt.checkpw() or Argon2Verifier
 * - Passwords must be hashed+salted, not compared directly
 */
public class SecureComparison {

    /**
     * Timing-safe string equality check.
     * Always takes the same time regardless of where strings differ.
     *
     * @param a First string (e.g., user-provided token)
     * @param b Second string (e.g., stored token)
     * @return true if strings are equal, false otherwise
     */
    public static boolean safeEquals(String a, String b) {
        if (a == null || b == null) {
            // Avoid NPE — null == null is true, null != non-null
            return (a == null) && (b == null);
        }
        
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        
        // ✅ MessageDigest.isEqual() is constant-time by JDK contract
        // It always iterates through the full length of both arrays
        return MessageDigest.isEqual(aBytes, bBytes);
    }

    /**
     * Timing-safe byte array equality check.
     * Prefer this for already-encoded values (HMAC, hash outputs).
     *
     * @param a First byte array
     * @param b Second byte array
     * @return true if arrays are equal, false otherwise
     */
    public static boolean safeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return (a == null) && (b == null);
        }
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Example: Verifying an API key safely.
     * 
     * In production, storedKey should be loaded from a secrets manager
     * (AWS Secrets Manager, HashiCorp Vault, etc.) — never hardcoded.
     */
    public boolean verifyApiKey(String providedKey, String storedKey) {
        if (providedKey == null || storedKey == null) {
            return false;
        }
        return safeEquals(providedKey, storedKey);  // ✅ no timing leak
    }

    /**
     * Example: Verifying a CSRF token safely.
     */
    public boolean verifyCsrfToken(String requestToken, String sessionToken) {
        if (requestToken == null || sessionToken == null) {
            return false;  // ✅ reject missing tokens explicitly
        }
        return safeEquals(requestToken, sessionToken);
    }

    // ===== For passwords, use a proper hashing library instead =====
    // 
    //   BCrypt (Spring Security):
    //   BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    //   boolean matches = encoder.matches(rawPassword, storedHash);
    //   → BCrypt.checkpw() is constant-time internally
    //
    //   Argon2 (Bouncy Castle / de.mkammerer):
    //   Argon2 argon2 = Argon2Factory.create();
    //   boolean matches = argon2.verify(encodedHash, password.toCharArray());
    //
    // Never compare plaintext passwords with equals() or even MessageDigest.isEqual()!
    // Always hash + salt first.
}
