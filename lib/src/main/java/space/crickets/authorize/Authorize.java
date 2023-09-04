package space.crickets.authorize;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The @Authorize annotation validates the JWT passed in to the annotated method.
 * If validation fails, an ForbiddenException is thrown, preventing method execution.
 * <p>
 * Validation entails:
 * 1) Ensuring that the JWT is not counterfeit.
 * 2) Ensuring that the JWT has not expired.
 * 3) Ensuring that the scopes listed in the JWT contain at least one of the declared scopes.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Authorize {

    /**
     * This has been named scopes instead of value() to make it explicit that the
     * validation happens on scopes, not other non-scope claims.
     */
    String[] scopes() default {};
}
