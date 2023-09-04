package space.crickets.authorize;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import io.jsonwebtoken.Claims;
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
import space.crickets.authorize.internals.ClaimsParser;
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
        public ClaimsParser claimsParser;
    }

    @Autowired HelloController subject;
    @Autowired ClaimsParser claimsParser;

    private static final String AUTHORIZATION = "j.w.t";
    private static final Claims DEFAULT_CLAIMS = claims("greeting.read");
    private static final String ROGER = "Roger";
    private static final String EXPECTED_RESPONSE = "Hello Roger";

    @Before public void setup() {
        reset(claimsParser);
    }

    @Test public void testAuthorizeAnnotation() {
        // JWT contains one of the required scopes
        when(claimsParser.parse(AUTHORIZATION)).thenReturn(DEFAULT_CLAIMS);

        assertEquals(
                EXPECTED_RESPONSE,
                subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );

        // JWT contains both of the required scopes
        reset(claimsParser);
        when(claimsParser.parse(AUTHORIZATION)).thenReturn(claims("greeting.write"));

        assertEquals(
                EXPECTED_RESPONSE,
                subject.getGreetingByName_checkScopes(ROGER, AUTHORIZATION)
        );

        // JWT contains both of the required scopes, AND more
        reset(claimsParser);
        when(claimsParser.parse(AUTHORIZATION)).thenReturn(
                claims(
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
        reset(claimsParser);
        when(claimsParser.parse(AUTHORIZATION)).thenReturn(claims("something-else"));

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
    private static Claims claims(String... scopes) {
        return new DefaultClaims(
                ImmutableMap.of(
                        "scp",
                        Lists.newArrayList(scopes)
                )
        );
    }
}
