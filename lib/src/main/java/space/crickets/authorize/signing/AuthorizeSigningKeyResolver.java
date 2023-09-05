package space.crickets.authorize.signing;

import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import space.crickets.authorize.exceptions.ForbiddenException;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

@Component
@Profile("!test")
public class AuthorizeSigningKeyResolver extends SigningKeyResolverAdapter {
    private final Request publicKeysRequest;
    private final OkHttpClient okHttpClient = new OkHttpClient();
    private final PublicKeyBuilder publicKeyBuilder = new PublicKeyBuilder();
    private static final Gson gson = new Gson();
    private final Lock lock = new ReentrantLock();
    private Instant rotatedAt = Instant.EPOCH; // i.e. not yet

    // Stores/caches public keys.
    // This is volatile so that its contents become visible to all other threads after a write operation immediately.
    private volatile Map<String, PublicKey> publicKeys = new HashMap<>();

    public AuthorizeSigningKeyResolver(@Qualifier("jwksUrl") String jwksUrl) {
        this.publicKeysRequest = new Request.Builder()
                .url(jwksUrl)
                .addHeader("Accept", "application/json")
                .get()
                .build();
    }

    /**
     * Done once at startup, then later as needed.
     */
    @PostConstruct
    public synchronized void fetchKeys() {
        try (Response response = okHttpClient.newCall(publicKeysRequest).execute()) {
            if (!response.isSuccessful()) {
                throw new RuntimeException("Call to " + publicKeysRequest.url() + " failed");
            }

            assert response.body() != null;
            JsonWebKeys jsonWebKeys = gson.fromJson(
                    response.body().string(),
                    JsonWebKeys.class
            );

            publicKeys.clear();
            jsonWebKeys.keys().forEach(jsonWebKey -> {
                PublicKey publicKey = publicKeyBuilder.buildPublicKey(jsonWebKey);
                publicKeys.put(jsonWebKey.kid(), publicKey); // should I clear out old keys?
            });

            rotatedAt = Instant.now();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Return the public key from the JWKS url given the key ID, either from local cache or over http.
     */
    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        String keyId = header.getKeyId();
        PublicKey publicKey = publicKeys.get(keyId);

        if (publicKey != null) {
            return publicKey;
        }

        // If it's null, the caller probably used a newly rotated-in key. Or it's a fake key id. DOS?

        lock.lock(); // First thread to reach this line goes in, the rest wait here.

        try {
            // When that first thread got to the 'finally' block and unlocked this lock, all the rest
            // of the queued up threads can benefit from the new keys being in our cache.
            publicKey = publicKeys.get(keyId);

            if (publicKey != null) {
                return publicKey;
            }

            // Assuming keys got rotated. Let's get the new ones. Only that first thread should hit this.
            Instant now = Instant.now();

            // Guard against some kind of Denial Of Service attack.
            if (RotationClock.hasBeenLongEnoughSinceLastRotation(rotatedAt)) {
                fetchKeys();
            }
        } finally {
            lock.unlock();
        }

        // Only that first thread should get here.
        publicKey = publicKeys.get(keyId);

        if (publicKey != null) {
            return publicKey;
        }

        // Hmm, someone asked for a key that's not in our newly updated cache. Could it be a key
        // from over 2 rotations ago? Or someone trying to hack in?
        throw new ForbiddenException("Unknown key id in JWT: " + keyId);
    }
}
