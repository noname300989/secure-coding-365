import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * UserProfileChallenge.java
 *
 * 🏋️ MINI CHALLENGE — Day 6
 *
 * Below is a BROKEN UserProfile class. Your task is to fix it
 * using proper encapsulation principles from today's lesson.
 *
 * ❌ BROKEN VERSION (what you start with):
 * ---------------------------------------
 *
 *   public class UserProfile {
 *       public String email;
 *       public String passwordHash;
 *       public int age;
 *       public List<String> roles = new ArrayList<>();
 *       public boolean isPremium;
 *
 *       public void setAge(int age) { this.age = age; }
 *       public List<String> getRoles() { return roles; }  // bug!
 *   }
 *
 * ✅ YOUR TASKS:
 *   1. Make all fields private
 *   2. Add input validation to setAge() — age must be 0–150
 *   3. Fix getRoles() to prevent external mutation
 *   4. Add a hasRole(String role) method for safe role checking
 *   5. Make email immutable (final) since it's the user's unique identifier
 *
 * A reference solution is provided below — try it yourself first!
 */
public final class UserProfile {

    // ✅ TODO: Fill in your solution here
    // Hint: private final String email; ... etc.

    // ---------- REFERENCE SOLUTION (collapse/hide while attempting!) ----------

    private final String email;        // final — the identifier never changes
    private String passwordHash;
    private int age;
    private final List<String> roles;
    private boolean isPremium;

    public UserProfile(String email, String passwordHash) {
        if (email == null || !email.contains("@"))
            throw new IllegalArgumentException("Invalid email address");
        if (passwordHash == null || passwordHash.isBlank())
            throw new IllegalArgumentException("Password hash is required");
        this.email = email;
        this.passwordHash = passwordHash;
        this.roles = new ArrayList<>();
        this.isPremium = false;
    }

    // email is immutable — getter only, no setter
    public String getEmail() { return email; }

    // ✅ Task 2: Validated setAge
    public void setAge(int age) {
        if (age < 0 || age > 150)
            throw new IllegalArgumentException("Age must be between 0 and 150, got: " + age);
        this.age = age;
    }
    public int getAge() { return age; }

    // ✅ Task 3: Defensive copy + unmodifiable view
    public List<String> getRoles() {
        return Collections.unmodifiableList(new ArrayList<>(roles));
    }

    // ✅ Task 4: Safe role check (no need to expose the list)
    public boolean hasRole(String role) {
        if (role == null) return false;
        return roles.contains(role);
    }

    public void addRole(String role) {
        if (role == null || role.isBlank())
            throw new IllegalArgumentException("Role cannot be blank");
        if (!roles.contains(role)) {
            roles.add(role);
        }
    }

    public void removeRole(String role) {
        roles.remove(role);
    }

    public boolean isPremium() { return isPremium; }
    public void setPremium(boolean premium) { this.isPremium = premium; }

    // ✅ Never expose passwordHash through toString!
    @Override
    public String toString() {
        return String.format("UserProfile{email='%s', age=%d, roles=%s, premium=%b}",
                email, age, getRoles(), isPremium);
    }

    public static void main(String[] args) {
        UserProfile user = new UserProfile("alice@example.com", "bcrypt$hash...");
        user.setAge(28);
        user.addRole("USER");
        user.addRole("ADMIN");

        System.out.println(user);
        System.out.println("Has USER role: " + user.hasRole("USER"));
        System.out.println("Has SUPERADMIN: " + user.hasRole("SUPERADMIN"));

        // ✅ Cannot tamper with roles list
        List<String> roles = user.getRoles();
        try {
            roles.add("SUPERADMIN"); // throws UnsupportedOperationException
        } catch (UnsupportedOperationException e) {
            System.out.println("Cannot inject roles externally: protected!");
        }

        // ✅ Invalid age rejected
        try {
            user.setAge(200); // throws IllegalArgumentException
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid age rejected: " + e.getMessage());
        }
    }
}
