package space.crickets.authorize.internals;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;
import space.crickets.authorize.Authorize;

import java.util.Arrays;

@Component
@Aspect
public class AuthorizeAnnotationAdvice {
    @Before("@annotation(authorize)")
    public void performAuthorizationChecks(JoinPoint joinPoint, Authorize authorize) {
        System.out.println(Arrays.toString(authorize.scopes()));
    }
}
