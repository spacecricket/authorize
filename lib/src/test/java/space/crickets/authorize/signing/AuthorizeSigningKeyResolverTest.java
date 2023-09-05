package space.crickets.authorize.signing;

import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultJwsHeader;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import space.crickets.authorize.exceptions.ForbiddenException;

import java.io.IOException;
import java.security.Key;
import java.time.Instant;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

/**
 * JwtParser comes from io.jsonwebtoken:jjwt-api. We don't want to test external code.
 * However, we build a JwtParser instance with our implementation of a SigningKeyResolver
 * - the AuthorizeSigningKeyResolver. This test covers correctness of AuthorizeSigningKeyResolver.
 * You'll notice that AuthorizeTest uses a mock JwtParser. So this functionality needs testing.
 */
public class AuthorizeSigningKeyResolverTest {
    private MockWebServer oauth2Server; // E.g. https://dev-850216.okta.com/oauth2/default
    private AuthorizeSigningKeyResolver subject;

    // Got these keys from https://dev-850216.okta.com/oauth2/default/v1/keys
    private static final JsonWebKey jsonWebKey1 = new JsonWebKey("txCrJUnxKH2jQ_Y9TsxiwMqVlBxJOdQlz0_RmUaJR3U", "2a6I2T9NvPHZZQWYYW6NAzo7svcOL0pTzrtG3oIr-1Ihl-DBTWm2HWCaKkbpuyEBCU4Q64Tc91mLme_urSilAINU11tRjAkl3HGkVzJDzCzoBdKB5E-SmcRvSW7oqvCEF7RJHr_V5KGeMBHqxIhas36ZpW7rmfhs4oUGhiffHR2PENKjVcaC1kyENLL1hGmJ3Lxf4RwKnjTsxRGA_VawE6Lf-mmIeSXnKEdZi8oD_vxqE7QZ_oJwzlv8ixT6_uUX5Lb-0Nm9LplId9U7HHcJT1vfBnTsd8h4L2sOECHKhj4N-ETXHEbOeVxZRW4llQTzzXgThGGOT06GhRqCsoaBPQ");
    private static final JsonWebKey jsonWebKey2 = new JsonWebKey("0Gdk1U_h3s-b2OSRMZZpIIkc7Q4spjxxtoAs-5R1dvQ", "yVrVpMPMBNbRxWDltMLDb3Ox-EdM0J-U2EhIB75GgPKqd8hyom6oA3qnz4QpHKPfYen9f5au34QOrre8GiUUTA2L-4JjzB6ldRqjo14EHLDXX0EelYEzeLOsA10SWKhm208y6VRHT4s7le3AkR0fAi6Q4tpoSoRTJj-Ek5huqTwT2vos_91FxuDlxfnK06UVBdCTUJwWtx2_Wbhb2hUKjjAk-mKG8kP7ftQEW14OrPaW9EH45y-h8iSg9Ogd3S0OQsRLwah7f6CMkzgJJ8FIv0vFsvrf4kf2mwZoHD_qiKHB8_8xYS5zBtGzlCwiahsd4bBfhKoMgb_ZUJOzL5YXcQ");

    private static final Claims CLAIMS = new DefaultClaims(); // We're not testing claims
    private static final Gson gson = new Gson();

    private static final Instant now = Instant.now();
    private static final Instant tenMinutesLater = now.plusSeconds(10 * 60);

    @Before
    public void setup() throws IOException {
        oauth2Server = new MockWebServer();
        oauth2Server.start();

        oauth2Server.enqueue(keysResponse(jsonWebKey1));

        subject = new AuthorizeSigningKeyResolver(
                oauth2Server.url("/v1/keys").toString()
        );

        subject.fetchKeys(); // Spring will call this because this method is annotated @PostConstruct.

        assertEquals(1, oauth2Server.getRequestCount());
    }

    @After
    public void tearDown() throws IOException {
        oauth2Server.shutdown();
    }


    /**
     * We shouldn't see an outbound http call because the local cache will have the key.
     */
    @Test
    public void validatePublicKeyConstruction() {
        Key publicKey = subject.resolveSigningKey(jwsHeader(jsonWebKey1), CLAIMS);
        assertNotNull(publicKey);
        assertEquals("RSA", publicKey.getAlgorithm());
        // Any more assertions and I'll be validating that java.security is correct!
    }

    /**
     * We shouldn't see an outbound http call because the local cache will have the key.
     */
    @Test
    public void whenRepeatedlyRequestingKey1() {
        subject.resolveSigningKey(jwsHeader(jsonWebKey1), CLAIMS);
        assertEquals(1, oauth2Server.getRequestCount());
        subject.resolveSigningKey(jwsHeader(jsonWebKey1), CLAIMS);
        assertEquals(1, oauth2Server.getRequestCount());
        subject.resolveSigningKey(jwsHeader(jsonWebKey1), CLAIMS);
        assertEquals(1, oauth2Server.getRequestCount());
    }

    /**
     * First, public-keys endpoint returns key 1 (covered by setup() above).
     * Then, a caller asks for key 2, assuming key 1 has been rotated out.
     * Validate that subject goes to the public-keys endpoint to get key 2.
     * <p>
     * Lastly, someone keeps quickly sending in key 1 (denial of service?). Let's be resilient to it.
     */
    @Test
    public void whenKey2IsRequested() {
        oauth2Server.enqueue(keysResponse(jsonWebKey2)); // i.e. no longer key1

        // 10 minutes later...
        try (MockedStatic<RotationClock> rotationClockMock = Mockito.mockStatic(RotationClock.class)) {
            rotationClockMock.when(() -> RotationClock.hasBeenLongEnoughSinceLastRotation(Mockito.any(Instant.class))).thenReturn(true);

            subject.resolveSigningKey(jwsHeader(jsonWebKey2), CLAIMS);
            assertEquals(2, oauth2Server.getRequestCount());

            // This time no outbound http call because the cache has key 2
            subject.resolveSigningKey(jwsHeader(jsonWebKey2), CLAIMS);
            assertEquals(2, oauth2Server.getRequestCount());

            // Ask for key 1 again. This is too soon since last re-fetch. 403?
            rotationClockMock.when(() -> RotationClock.hasBeenLongEnoughSinceLastRotation(Mockito.any(Instant.class))).thenReturn(false);
            assertThrows(
                    ForbiddenException.class,
                     () -> subject.resolveSigningKey(jwsHeader(jsonWebKey1), CLAIMS)
            );
            assertEquals(2, oauth2Server.getRequestCount()); // still 2
        }
    }

    /**
     * Represents the response from an Oauth2 server public-keys endpoint. E.g.:
     * ```
     * {
     *     "keys":
     *     [
     *         {
     *             "kty": "RSA",
     *             "alg": "RS256",
     *             "kid": "0Gdk1U_h3s-b2OSRMZZpIIkc7Q4spjxxtoAs-5R1dvQ",
     *             "use": "sig",
     *             "e": "AQAB",
     *             "n": "yVrVpMPMBNbRxWDltMLDb3Ox-EdM0J-U2EhIB75GgPKqd8hyom6oA3qnz4QpHKPfYen9f5au34QOrre8GiUUTA2L-4JjzB6ldRqjo14EHLDXX0EelYEzeLOsA10SWKhm208y6VRHT4s7le3AkR0fAi6Q4tpoSoRTJj-Ek5huqTwT2vos_91FxuDlxfnK06UVBdCTUJwWtx2_Wbhb2hUKjjAk-mKG8kP7ftQEW14OrPaW9EH45y-h8iSg9Ogd3S0OQsRLwah7f6CMkzgJJ8FIv0vFsvrf4kf2mwZoHD_qiKHB8_8xYS5zBtGzlCwiahsd4bBfhKoMgb_ZUJOzL5YXcQ"
     *         }
     *     ]
     * }
     * ```
     */
    private MockResponse keysResponse(JsonWebKey jsonWebKey) {
        return new MockResponse().setBody(gson.toJson(new JsonWebKeys(jsonWebKey)));
    }

    private DefaultJwsHeader jwsHeader(JsonWebKey jsonWebKey) {
        return new DefaultJwsHeader(Map.of("kid", jsonWebKey.kid()));
    }
}