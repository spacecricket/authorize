package space.crickets.authorize;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.security.SignatureException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import space.crickets.authorize.exceptions.ForbiddenException;
import space.crickets.authorize.testhelpers.HelloController;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Ensures the various annotations work.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {
        AppConfig.class, // The main configuration
        AuthorizeTest.TestConfig.class // Test overrides
})
public class AuthorizeTest {

    @Configuration
    @Import(HelloController.class)
    public static class TestConfig {
        /*
         * An actual JwtParser only works with valid JWTs. It's far too much trouble to create valid JWTs that
         * have valid signatures and are unexpired.
         */
        @MockBean
        public JwtParser jwtParser;
    }

    @Autowired HelloController subject;
    @Autowired JwtParser jwtParser;

    private static final String AUTHORIZATION = "Bearer j.w.t";
    private static final String ROGER = "Roger";
    private static final String HELLO_ROGER = "Hello Roger";
    private static final int AGE = 14;

    @Test public void whenNoScopeIsRequired() {
        // JWT contains some scope
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(jwt(ROGER, AGE, "greeting.read"));

        assertEquals(
                HELLO_ROGER,
                subject.getGreetingByName_checkNoScope(ROGER, AUTHORIZATION)
        );
    }

    @Test public void whenJwtContainsOneOfTheRequiredScopes() {
        // JWT contains one of the required scopes
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(jwt(ROGER, AGE, "greeting.read"));

        assertEquals(
                HELLO_ROGER,
                subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );
    }

    @Test public void whenJwtContainsMoreThanOneOfTheRequiredScopes() {
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(
                jwt(
                        ROGER,
                        AGE,
                        "greeting.read",
                        "greeting.write",
                        "something-else"
                )
        );

        assertEquals(
                HELLO_ROGER,
                subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );
    }

    @Test public void whenJwtLacksAnyOfTheRequiredScopes() {
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(jwt(ROGER, AGE, "something-else"));

        assertThrows(
                ForbiddenException.class,
                () -> subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );
    }

    @Test public void whenJwtParsingFailsWithExpiredJwtException() {
        when(jwtParser.parse(AUTHORIZATION)).thenThrow(ExpiredJwtException.class);

        assertThrows(
                ForbiddenException.class,
                () -> subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );
    }

    @Test public void whenJwtParsingFailsWithMalformedJwtException() {
        when(jwtParser.parse(AUTHORIZATION)).thenThrow(MalformedJwtException.class);

        assertThrows(
                ForbiddenException.class,
                () -> subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );
    }

    @Test public void whenJwtParsingFailsWithSignatureException() {
        when(jwtParser.parse(AUTHORIZATION)).thenThrow(SignatureException.class);

        assertThrows(
                ForbiddenException.class,
                () -> subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );
    }

    @Test public void whenJwtParsingFailsWithIllegalArgumentException() {
        when(jwtParser.parse(AUTHORIZATION)).thenThrow(IllegalArgumentException.class);

        assertThrows(
                ForbiddenException.class,
                () -> subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );
    }

    @Test public void whenJwtParsingFailsWithAnUnexpectedException() {
        when(jwtParser.parse(AUTHORIZATION)).thenThrow(IndexOutOfBoundsException.class);

        assertThrows(
                IndexOutOfBoundsException.class, // not ForbiddenException
                () -> subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );
    }

    @Test public void whenNameAndAgeMatchClaims() {
        // JWT contains one of the required scopes
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(jwt(ROGER, AGE, "greeting.read"));

        assertEquals(
                HELLO_ROGER,
                subject.getGreetingByName_matchNameAndAge(ROGER, AGE, AUTHORIZATION)
        );
    }

    @Test public void whenNameDoesNotMatchClaim() {
        // JWT contains one of the required scopes
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(jwt("Rafael", AGE, "greeting.read"));

        assertThrows(
                ForbiddenException.class,
                () -> subject.getGreetingByName_matchNameAndAge(ROGER, AGE, AUTHORIZATION)
        );
    }

    @Test public void whenAgeDoesNotMatchClaim() {
        // JWT contains one of the required scopes
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(jwt(ROGER, 17, "greeting.read"));

        assertThrows(
                ForbiddenException.class,
                () -> subject.getGreetingByName_matchNameAndAge(ROGER, AGE, AUTHORIZATION)
        );
    }

//    @Test public void testBindClaim() {
//        String response = subject.getGreetingByName_checkScopesAndMatchNameAndCheckAge("Roger", null,"");
//        assertEquals("Hello Roger", response);
//    }

    /**
     * Helper that returns a Claims object containing the provided scopes, full name and age claims.
     */
    private static <H extends Header<H>> io.jsonwebtoken.Jwt<H, Claims> jwt(String fullName, int age, String... scopes) {
        return new Jwt<>(
                new DefaultClaims(
                        ImmutableMap.of(
                                "scp", Lists.newArrayList(scopes),
                                "full-name", fullName,
                                "age", age
                        )
                )
        );
    }

    /**
     * This class makes it easier to mock jwts.
     */
    private record Jwt<H extends Header<H>>(Claims claims) implements io.jsonwebtoken.Jwt<H, Claims> {
        @Override
            public H getHeader() {
                return null;
            }

            @Override
            public Claims getBody() {
                return claims;
            }
        }
}
