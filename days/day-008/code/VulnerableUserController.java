// VulnerableUserController.java
// VULNERABLE: Multiple error handling security flaws — DO NOT USE IN PRODUCTION

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.io.*;

@RestController
public class VulnerableUserController {

    @Autowired
    private UserRepository userRepo;

    // ❌ VULNERABLE: Leaks DB schema, stack trace, internal paths
    @GetMapping("/users/{id}")
    public ResponseEntity<String> getUser(@PathVariable String id) {
        try {
            User user = userRepo.findById(Integer.parseInt(id));
            return ResponseEntity.ok(user.toString());

        } catch (NumberFormatException e) {
            // Leaks the invalid input back to attacker + exception type
            return ResponseEntity
                .status(400)
                .body("Invalid ID: " + id + "\n" + e.toString());   // CWE-209

        } catch (SQLException e) {
            // ☠️ Attacker sees your DB type, table names, column names!
            e.printStackTrace(); // goes to stderr — sometimes captured in error pages
            return ResponseEntity
                .status(500)
                .body("Database error: " + e.getMessage());          // CWE-209

        } catch (Exception e) {
            // ☠️ Nuclear option: dumps EVERYTHING to HTTP response
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return ResponseEntity
                .status(500)
                .body("Error occurred: " + sw.toString());           // Full stack trace!
        }
    }

    // ❌ VULNERABLE: Silent failure — CWE-390
    @PostMapping("/users/transfer")
    public ResponseEntity<String> transferFunds(@RequestBody TransferRequest req) {
        try {
            fundService.transfer(req.getFrom(), req.getTo(), req.getAmount());
            return ResponseEntity.ok("Transfer complete");
        } catch (Exception e) {
            // ☠️ Silent fail — transaction may be partially complete!
            // Nobody knows this failed. No log. No alert. Money may be lost.
            return ResponseEntity.ok("Transfer complete"); // LYING to the user!
        }
    }
}
