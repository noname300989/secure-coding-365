/**
 * SECURE: RoleEnum.java
 * 
 * Type-safe role model using Java enums.
 * 
 * Benefits over String-based roles:
 * - Compile-time type safety: invalid roles can't be passed
 * - No fall-through risk: each enum value has exactly one access level
 * - IDE autocomplete and refactoring support
 * - Impossible to create unknown roles at runtime from enum type
 * - Can add methods, permissions, and hierarchy directly to the enum
 */
public enum RoleEnum {

    // Enum constants with associated access levels
    GUEST(1, "Can view public content only"),
    USER(2, "Can view and create personal content"),
    MODERATOR(5, "Can moderate community content"),
    ADMIN(10, "Full system access");

    private final int accessLevel;
    private final String description;

    // Constructor
    RoleEnum(int accessLevel, String description) {
        this.accessLevel = accessLevel;
        this.description = description;
    }

    public int getAccessLevel() {
        return accessLevel;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Check if this role has at least the required access level.
     * 
     * Example: Role.MODERATOR.hasAtLeast(Role.USER) → true
     *          Role.GUEST.hasAtLeast(Role.ADMIN) → false
     */
    public boolean hasAtLeast(RoleEnum required) {
        return this.accessLevel >= required.accessLevel;
    }

    /**
     * Safe role lookup from String (e.g., from database or HTTP request).
     * Returns null if the role string is invalid — never throws.
     * 
     * ✅ Safe: invalid input returns null, never a privileged role
     * ✅ Caller must handle null (can't accidentally use it as a valid role)
     */
    public static RoleEnum fromString(String roleName) {
        if (roleName == null) return null;
        try {
            return RoleEnum.valueOf(roleName.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;  // Unknown role — deny by default
        }
    }
}

/**
 * Usage example:
 *
 *   // In a controller:
 *   RoleEnum userRole = RoleEnum.fromString(user.getRoleString());
 *   if (userRole == null || !userRole.hasAtLeast(RoleEnum.MODERATOR)) {
 *       throw new AccessDeniedException("Insufficient permissions");
 *   }
 *
 *   // Direct use:
 *   int level = RoleEnum.ADMIN.getAccessLevel();   // Always 10, no fall-through
 *   boolean canModerate = RoleEnum.MODERATOR.hasAtLeast(RoleEnum.USER);  // true
 *   boolean canAdmin = RoleEnum.USER.hasAtLeast(RoleEnum.ADMIN);          // false
 */
