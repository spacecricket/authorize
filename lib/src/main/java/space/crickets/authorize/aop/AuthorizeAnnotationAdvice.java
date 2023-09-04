package space.crickets.authorize.aop;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import space.crickets.authorize.Authorize;
import space.crickets.authorize.Jwt;
import space.crickets.authorize.exceptions.ForbiddenException;

import java.lang.reflect.Parameter;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
@Aspect
public class AuthorizeAnnotationAdvice {
    private final JwtParser jwtParser;

    public AuthorizeAnnotationAdvice(JwtParser jwtParser) {
        this.jwtParser = jwtParser;
    }

    @Before("@annotation(authorize)")
    public void performAuthorizationChecks(JoinPoint joinPoint, Authorize authorize) {
        Set<String> requiredScopes = new HashSet<>(List.of(authorize.scopes()));

        // Grab the JWT
        MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = methodSignature.getMethod().getParameters();
        Object[] actualArgs = joinPoint.getArgs();

        for (int i = 0; i < parameters.length; i++) {
            Parameter parameter = parameters[i];
            Object actualArg = actualArgs[i];

            if (parameter.isAnnotationPresent(Jwt.class)) {
                Claims claims;

                try {
                    claims = (Claims) jwtParser.parse((String) actualArg).getBody();
                } catch (ExpiredJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
                    throw new ForbiddenException("Unable to parse JWT", e);
                }

                if (requiredScopes.isEmpty()) {
                    return; // no scope is required to be in the JWT
                }

                for (Object scopeObj : claims.get("scp", List.class)) {
                    if (requiredScopes.contains((String) scopeObj)) {
                        return; // one of the required scopes was found in the JWT
                    }
                }
            }
        }

        throw new ForbiddenException("JWT did not contain any of these scopes: " + requiredScopes);
    }
}
