package space.crickets.authorize;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.impl.DefaultClaims;
import org.junit.Before;
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
        @MockBean
        public JwtParser jwtParser; // override the actual JwtParser
    }

    @Autowired HelloController subject;
    @Autowired JwtParser jwtParser;

    private static final String AUTHORIZATION = "j.w.t";
    private static final String ROGER = "Roger";
    private static final String EXPECTED_RESPONSE = "Hello Roger";

    @Before public void setup() {
        reset(jwtParser);
    }

    @Test public void testAuthorizeAnnotation() {
        // JWT contains one of the required scopes
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(jwt("greeting.read"));

        assertEquals(
                EXPECTED_RESPONSE,
                subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );

        // JWT contains both of the required scopes
        reset(jwtParser);
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(jwt("greeting.write"));

        assertEquals(
                EXPECTED_RESPONSE,
                subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );

        // JWT contains both of the required scopes, AND more
        reset(jwtParser);
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(
                jwt(
                        "greeting.read",
                        "greeting.write",
                        "something-else"
                )
        );

        assertEquals(
                EXPECTED_RESPONSE,
                subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );

        // JWT does not contain any of the required scopes
        reset(jwtParser);
        when(jwtParser.parse(AUTHORIZATION)).thenReturn(jwt("something-else"));

        assertThrows(
                ForbiddenException.class,
                () -> subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );
    }

//    @Test public void testMatchClaim() {
//        String response = subject.getGreetingByName_checkScopesAndMatchName("Roger", "");
//        assertEquals("Hello Roger", response);
//    }
//
//    @Test public void testBindClaim() {
//        String response = subject.getGreetingByName_checkScopesAndMatchNameAndCheckAge("Roger", null,"");
//        assertEquals("Hello Roger", response);
//    }

    /**
     * Helper that returns a Claims object containing the provided scopes.
     */
    private static <H extends Header<H>> io.jsonwebtoken.Jwt<H, Claims> jwt(String... scopes) {
        return new Jwt<>(
                new DefaultClaims(ImmutableMap.of("scp", Lists.newArrayList(scopes)))
        );
    }

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
