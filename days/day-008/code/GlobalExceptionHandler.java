// GlobalExceptionHandler.java
// Spring @ControllerAdvice: centralized, consistent exception-to-HTTP-response mapping

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Handles all AppException subclasses (ResourceNotFoundException, ValidationException, etc.)
     * Logs internal detail at WARN, returns safe user message + correlation ID.
     */
    @ExceptionHandler(AppException.class)
    public ResponseEntity<ApiResponse> handleAppException(AppException ex) {
        log.warn("[{}] AppException: {}", ex.getCorrelationId(), ex.getMessage());
        return ResponseEntity.status(400)
            .body(new ApiResponse(
                ex.getUserMessage() + " Ref: " + ex.getCorrelationId(),
                null
            ));
    }

    /**
     * Catch-all handler: logs full stack trace internally, returns opaque 500 response.
     * The correlationId allows operators to grep logs for the exact error.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleGenericException(Exception ex, HttpServletRequest req) {
        String correlationId = UUID.randomUUID().toString();
        log.error("[{}] Unhandled exception at {} {}: {}",
            correlationId, req.getMethod(), req.getRequestURI(), ex.getMessage(), ex);
        return ResponseEntity.status(500)
            .body(new ApiResponse("Internal server error. Ref: " + correlationId, null));
    }
}
