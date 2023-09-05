package space.crickets.authorize.aop;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import space.crickets.authorize.Authorize;
import space.crickets.authorize.BindClaim;
import space.crickets.authorize.Jwt;
import space.crickets.authorize.MatchClaim;
import space.crickets.authorize.exceptions.ForbiddenException;

import java.lang.reflect.Parameter;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * How this works: <a href="https://docs.spring.io/spring-framework/reference/core/aop/ataspectj/advice.html">Spring AOP</a>
 */
@Component
@Aspect
public class AuthorizeAdvice {
    private final JwtParser jwtParser;

    public AuthorizeAdvice(JwtParser jwtParser) {
        this.jwtParser = jwtParser;
    }

    @Around("@annotation(authorize)")
    public Object performAuthorizationChecks(ProceedingJoinPoint joinPoint, Authorize authorize) throws Throwable {
        io.jsonwebtoken.Jwt<?, Claims> jwt = verifyJwt(joinPoint);

        Claims claims = jwt.getBody();

        verifyScopes(authorize, claims);

        verifyClaims(joinPoint, claims);

        Object[] updatedArgs = bindClaims(joinPoint, claims);

        return joinPoint.proceed(updatedArgs);
    }

    private io.jsonwebtoken.Jwt<?, Claims> verifyJwt(JoinPoint joinPoint) {
        // Grab the JWT
        MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = methodSignature.getMethod().getParameters();
        Object[] actualArgs = joinPoint.getArgs();

        for (int i = 0; i < parameters.length; i++) {
            Parameter parameter = parameters[i];
            Object actualArg = actualArgs[i];

            if (parameter.isAnnotationPresent(Jwt.class)) {
                try {
                    return jwtParser.parse((String) actualArg);
                } catch (ExpiredJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
                    throw new ForbiddenException("Unable to parse JWT", e);
                }
            }
        }

        throw new RuntimeException("@Jwt annotation not found in Controller method definition");
    }

    private void verifyScopes(Authorize authorize, Claims claims) {
        if (authorize.scopes().length > 0) {
            Set<String> requiredScopes = new HashSet<>(List.of(authorize.scopes()));

            for (Object scopeObj : claims.get("scp", List.class)) {
                if (requiredScopes.contains((String) scopeObj)) {
                    return; // bingo!
                }
            }

            throw new ForbiddenException("JWT does not have any of these scopes: " + requiredScopes);
        }
    }

    private void verifyClaims(JoinPoint joinPoint, Claims claims) {
        MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = methodSignature.getMethod().getParameters();
        Object[] actualArgs = joinPoint.getArgs();

        for (int i = 0; i < parameters.length; i++) {
            Parameter parameter = parameters[i];
            Object arg = actualArgs[i];

            if (parameter.isAnnotationPresent(MatchClaim.class)) {
                MatchClaim matchClaim = parameter.getAnnotation(MatchClaim.class);
                String claimName = matchClaim.value();

                if (claims.containsKey(claimName)) {
                    Object claimValue = claims.get(claimName);

                    if (!Objects.equals(arg, claimValue)) {
                        throw new ForbiddenException(
                                String.format("JWT Claim %s is %s, but argument is %s", claimName, claimValue, arg)
                        );
                    }
                } else {
                    throw new ForbiddenException("JWT is missing claim: " + claimName);
                }
            }
        }
    }

    private Object[] bindClaims(ProceedingJoinPoint joinPoint, Claims claims) {
        MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = methodSignature.getMethod().getParameters();
        Object[] updatedArgs = joinPoint.getArgs();

        for (int i = 0; i < parameters.length; i++) {
            Parameter parameter = parameters[i];

            if (parameter.isAnnotationPresent(BindClaim.class)) {
                BindClaim bindClaim = parameter.getAnnotation(BindClaim.class);
                String claimName = bindClaim.value();

                if (claims.containsKey(claimName)) {
                    updatedArgs[i] = claims.get(claimName);
                }
            }
        }

        return updatedArgs;
    }
}
