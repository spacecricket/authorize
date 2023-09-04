package space.crickets.authorize.exceptions;

/**
 * Indicates that JWT verification failed. Spring Boot applications should intercept these to return the
 * 403 response code.
 */
public class ForbiddenException extends RuntimeException {
    public ForbiddenException(String message) {
        super(message);
    }

    public ForbiddenException(String message, Throwable cause) {
        super(message, cause);
    }
}
