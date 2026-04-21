// VulnerableUserService.java
// ❌ DO NOT USE — demonstrates common input validation vulnerabilities
//
// CWE-20:  Improper Input Validation (registerUser accepts null/blank/malicious input)
// CWE-476: NULL Pointer Dereference (transferFunds crashes if user not found)
// CWE-129: Improper Validation of Array Index (getUserByIndex accepts -1 or MAX_VALUE)
// CWE-252: Unchecked Return Value (deleteUser ignores boolean result of remove())
// CWE-117: Improper Output Neutralization for Logs (log injection via requestedBy)

import java.util.*;

public class VulnerableUserService {

    private List<String> users = new ArrayList<>();
    private Map<String, Integer> balances = new HashMap<>();

    // 🚨 PROBLEM 1: No null check, no length check, no format check
    // registerUser(null, null) → NullPointerException throughout the app
    // registerUser("<script>alert(1)</script>", ...) → XSS payload stored
    public void registerUser(String username, String email) {
        users.add(username);
        balances.put(email, 0);
        System.out.println("Registered: " + username);
    }

    // 🚨 PROBLEM 2: Negative amounts not blocked
    // transferFunds(-10000, "attacker", "attacker"):
    //   attacker's balance goes from 0 to 0 - (-10000) = +10000 (self-transfer!)
    //   This is a classic business logic bypass + CWE-682 Incorrect Calculation
    // balances.get(fromUser) throws NullPointerException if fromUser doesn't exist in map
    public boolean transferFunds(int amount, String fromUser, String toUser) {
        int from = balances.get(fromUser); // NPE if key missing (CWE-476)
        int to   = balances.get(toUser);
        balances.put(fromUser, from - amount); // negative amount = credit!
        balances.put(toUser, to + amount);
        return true; // always returns true — never checks if semantically valid
    }

    // 🚨 PROBLEM 3: No index bounds check → IndexOutOfBoundsException = DoS
    // getUserByIndex(-1, ...) or getUserByIndex(Integer.MAX_VALUE, ...) → crash
    //
    // Log injection: if requestedBy = "admin\nINFO: Privilege escalation successful"
    // → the fake line appears in the log file as if it were a real system event
    public String getUserByIndex(int index, String requestedBy) {
        String user = users.get(index); // CWE-129: no range validation
        // CWE-117: raw unsanitized input from requestedBy injected into log
        System.out.println("INFO: " + requestedBy + " accessed user " + user);
        return user;
    }

    // 🚨 PROBLEM 4: Return value of critical operation silently ignored
    // users.remove("nonexistentUser") returns FALSE but we never check
    // We log "success" even though the delete never happened (CWE-252)
    public void deleteUser(String username) {
        boolean removed = users.remove(username); // false if not found — IGNORED
        balances.remove(username);
        System.out.println("User " + username + " deleted successfully"); // always printed!
    }
}
