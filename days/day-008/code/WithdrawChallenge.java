// WithdrawChallenge.java
// CHALLENGE: Fix all 6 security issues in this vulnerable withdrawal endpoint.
// See README.md for the full list of issues to find.

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.math.BigDecimal;

@RestController
public class WithdrawChallenge {

    @Autowired private AccountService accountService;
    @Autowired private DatabaseService db;

    // TODO: Fix this method — it has 6 security/reliability issues.
    @PostMapping("/accounts/{id}/withdraw")
    public String withdraw(@PathVariable String id,
                           @RequestParam String amount) {
        try {
            Account acct = db.getAccount(id);
            BigDecimal amt = new BigDecimal(amount);
            acct.debit(amt);
            db.save(acct);
            return "OK: withdrew " + amount + " from account " + id;
        } catch (Exception e) {
            return "Error: " + e.getMessage() + "\n" + e.getStackTrace()[0]; // ← issues here
        }
    }
}

/*
 * Issues to fix:
 * 1. Error message leaks internal exception detail (CWE-209)
 * 2. Stack trace element exposed in HTTP response (CWE-209)
 * 3. No correlation ID — impossible to trace error in logs
 * 4. `catch (Exception e)` too broad — need specific handling for NumberFormatException, AccountNotFoundException, InsufficientFundsException
 * 5. Success message echoes raw user input (amount, id) — potential reflected injection
 * 6. No atomicity: if db.save() fails after acct.debit(), balance is corrupted
 *
 * Bonus: Refactor so this method delegates to @ControllerAdvice and just re-throws.
 */
