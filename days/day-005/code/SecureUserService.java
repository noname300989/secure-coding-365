// SecureUserService.java
// ✅ Secure version — all input validated via InputValidator utility
//
// Fixes:
//   CWE-20:  Validates username (allowlist) and email (format+length) before use
//   CWE-476: Uses getOrDefault() with sentinel value instead of get() that can return null
//   CWE-129: Validates index is within [0, size-1] before list access
//   CWE-252: Checks return value of remove() and throws on failure
//   CWE-117: Allowlist validation on requestedBy strips newlines (log injection prevention)
//   Business logic: amount constrained to [1, MAX_TRANSFER]; self-transfer blocked

import java.util.*;
import java.util.logging.*;

public class SecureUserService {

    private static final Logger LOG = Logger.getLogger(SecureUserService.class.getName());

    private final List<String> users   = new ArrayList<>();
    private final Map<String, Integer> balances = new HashMap<>();

    // Business rule: max single transfer amount
    private static final int MAX_TRANSFER = 100_000;

    /**
     * Registers a new user.
     * Validates username (allowlist) and email (format) before any state changes.
     *
     * @param username alphanumeric + underscore + hyphen, max 50 chars
     * @param email    valid RFC 5321 email address
     * @throws IllegalArgumentException if either input is invalid
     * @throws IllegalStateException    if username is already taken
     */
    public void registerUser(String username, String email) {
        // Validate before touching any state — fail fast
        String safeUsername = InputValidator.validateUsername(username);
        String safeEmail    = InputValidator.validateEmail(email);

        if (users.contains(safeUsername)) {
            throw new IllegalStateException("Username already taken: " + safeUsername);
        }

        users.add(safeUsername);
        balances.put(safeEmail, 0);
        LOG.info("User registered: " + safeUsername); // safe — passed allowlist validation
    }

    /**
     * Transfers funds from one user to another.
     * Amount must be positive and within daily limit. Users must exist and sender
     * must have sufficient funds.
     *
     * @param amount   transfer amount in cents (must be 1 – MAX_TRANSFER)
     * @param fromUser sender username
     * @param toUser   recipient username
     * @return true if transfer succeeded
     * @throws IllegalArgumentException if inputs are invalid or users don't exist
     * @throws IllegalStateException    if sender has insufficient funds
     */
    public boolean transferFunds(int amount, String fromUser, String toUser) {
        // 1. Validate all parameters first
        int safeAmount  = InputValidator.requireInRange(amount, 1, MAX_TRANSFER, "amount");
        String safeFrom = InputValidator.validateUsername(fromUser);
        String safeTo   = InputValidator.validateUsername(toUser);

        // 2. Business logic validation: no self-transfer
        if (safeFrom.equals(safeTo)) {
            throw new IllegalArgumentException("Cannot transfer to yourself");
        }

        // 3. Use getOrDefault(-1) as sentinel — avoids NullPointerException
        int fromBalance = balances.getOrDefault(safeFrom, -1);
        int toBalance   = balances.getOrDefault(safeTo,   -1);

        if (fromBalance < 0) throw new IllegalArgumentException("Sender not found: " + safeFrom);
        if (toBalance   < 0) throw new IllegalArgumentException("Recipient not found: " + safeTo);

        // 4. Sufficient funds check
        if (fromBalance < safeAmount) {
            throw new IllegalStateException("Insufficient funds for transfer");
        }

        // 5. Execute transfer
        balances.put(safeFrom, fromBalance - safeAmount);
        balances.put(safeTo,   toBalance   + safeAmount);

        // Log amount and event; never log user balances
        LOG.info("Transfer of " + safeAmount + " cents completed successfully");
        return true;
    }

    /**
     * Returns the username at the given list index.
     * Validates index bounds. Sanitizes requester identity before logging.
     *
     * @param index       list index (0 to size-1)
     * @param requestedBy username of the requestor (validated to prevent log injection)
     * @return username at index
     * @throws IllegalArgumentException if index is out of range or requestedBy is invalid
     */
    public String getUserByIndex(int index, String requestedBy) {
        // Validate index within [0, size-1]
        InputValidator.requireInRange(index, 0, users.size() - 1, "index");

        // Validate requestedBy with allowlist — strips newlines/special chars
        // This prevents log injection (CWE-117)
        String safeRequester = InputValidator.validateUsername(requestedBy);

        String user = users.get(index);

        // Audit log: who accessed a record, not what the record contains
        LOG.info("User record at index " + index + " accessed by: " + safeRequester);
        return user;
    }

    /**
     * Deletes a user from the system.
     * Checks the boolean return value of remove() — throws if user wasn't found.
     *
     * @param username user to delete
     * @throws IllegalArgumentException if username is invalid
     * @throws NoSuchElementException   if user does not exist
     */
    public void deleteUser(String username) {
        String safeUsername = InputValidator.validateUsername(username);

        // Check return value — CWE-252 fix
        boolean removed = users.remove(safeUsername);
        if (!removed) {
            // Throw so callers know the operation didn't happen
            throw new NoSuchElementException("User not found: " + safeUsername);
        }

        balances.remove(safeUsername);
        LOG.info("User deleted: " + safeUsername);
    }
}
