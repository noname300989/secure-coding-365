// SecureExceptionHierarchy.java
// Demonstrates custom exception classes that separate user-facing messages from internal details

import java.util.UUID;

/**
 * Base application exception.
 * - super() message = internal detail (logged only, never shown to user)
 * - userMessage = safe string shown in HTTP response
 * - correlationId = ties the log entry to the user-visible reference
 */
public class AppException extends RuntimeException {

    private final String correlationId;
    private final String userMessage;

    public AppException(String internalMessage, String userMessage,
                        String correlationId, Throwable cause) {
        super(internalMessage, cause); // internal detail stays in logs ONLY
        this.userMessage = userMessage;
        this.correlationId = correlationId;
    }

    public String getUserMessage() { return userMessage; }
    public String getCorrelationId() { return correlationId; }
    // NO getter for the internal (super) message — intentional!
}

/**
 * Thrown when a requested resource is not found.
 * Internal: "User id=42 not found in db.users"
 * User-facing: "The requested resource was not found."
 */
public class ResourceNotFoundException extends AppException {
    public ResourceNotFoundException(String internalDetail, String correlationId) {
        super(
            internalDetail,
            "The requested resource was not found.",
            correlationId,
            null
        );
    }
}

/**
 * Thrown for validation failures.
 */
public class ValidationException extends AppException {
    public ValidationException(String internalDetail, String userMessage, String correlationId) {
        super(internalDetail, userMessage, correlationId, null);
    }
}
