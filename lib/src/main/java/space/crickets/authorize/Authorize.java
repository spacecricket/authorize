package space.crickets.authorize;

public @interface Authorize {
    String[] scopes() default {};
}
