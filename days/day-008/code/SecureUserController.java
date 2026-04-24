// SecureUserController.java
// Demonstrates secure exception handling: correlation IDs, safe error responses, try-with-resources

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
public class SecureUserController {

    private static final Logger log = LoggerFactory.getLogger(SecureUserController.class);

    @Autowired private UserRepository userRepo;
    @Autowired private DataSource dataSource;

    @GetMapping("/users/{id}")
    public ResponseEntity<ApiResponse> getUser(@PathVariable String id) {
        // Correlation ID generated server-side (never from user input)
        String correlationId = UUID.randomUUID().toString();

        int userId;
        try {
            userId = Integer.parseInt(id);
        } catch (NumberFormatException e) {
            // Safe: only log the fact of bad input, NOT the raw input value at ERROR level
            log.warn("[{}] Invalid user ID format received", correlationId);
            return ResponseEntity.badRequest()
                .body(new ApiResponse("Invalid request. Ref: " + correlationId, null));
        }

        try {
            User user = userRepo.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(
                    "User id=" + userId + " not found in users table", // internal only
                    correlationId
                ));

            return ResponseEntity.ok(new ApiResponse("success", user.toPublicDTO()));

        } catch (ResourceNotFoundException e) {
            // Internal detail logged; user gets only the safe message
            log.warn("[{}] Resource not found: {}", e.getCorrelationId(), e.getMessage());
            return ResponseEntity.status(404)
                .body(new ApiResponse(e.getUserMessage() + " Ref: " + e.getCorrelationId(), null));

        } catch (Exception e) {
            // Catch-all: full stack trace in logs, NOTHING useful in response
            log.error("[{}] Unexpected error in getUser for userId={}", correlationId, userId, e);
            return ResponseEntity.status(500)
                .body(new ApiResponse("An unexpected error occurred. Ref: " + correlationId, null));
        }
    }

    // ✅ Try-with-resources: connection always closed even if exception thrown
    @GetMapping("/users/{id}/profile")
    public ResponseEntity<ApiResponse> getUserProfile(@PathVariable int id) {
        String correlationId = UUID.randomUUID().toString();
        String sql = "SELECT * FROM user_profiles WHERE user_id = ?";

        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    throw new ResourceNotFoundException(
                        "Profile for user_id=" + id + " not found", correlationId);
                }
                UserProfile profile = mapProfile(rs);
                return ResponseEntity.ok(new ApiResponse("success", profile));
            }

        } catch (ResourceNotFoundException e) {
            log.warn("[{}] {}", e.getCorrelationId(), e.getMessage());
            return ResponseEntity.status(404)
                .body(new ApiResponse(e.getUserMessage() + " Ref: " + e.getCorrelationId(), null));

        } catch (SQLException e) {
            // SQL exception detail NEVER goes to user
            log.error("[{}] DB error fetching profile for user_id={}", correlationId, id, e);
            return ResponseEntity.status(500)
                .body(new ApiResponse("Service unavailable. Ref: " + correlationId, null));
        }
        // Connection and PreparedStatement auto-closed by try-with-resources — no finally needed!
    }
}
