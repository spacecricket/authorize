package space.crickets.authorize.signing;

import space.crickets.authorize.exceptions.ForbiddenException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * This class generates a `java.security.PublicKey` from the response of an Oauth server's public-keys endpoint.
 * Googled around to come up with this.
 */
public class PublicKeyBuilder {
    public PublicKey buildPublicKey(JsonWebKey jsonWebKey) {
        if (jsonWebKey.kty().equalsIgnoreCase("RSA") && jsonWebKey.use().equalsIgnoreCase("sig")) {

            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(
                    new BigInteger(1, Base64.getUrlDecoder().decode(jsonWebKey.n())),
                    new BigInteger(1, Base64.getUrlDecoder().decode(jsonWebKey.e()))
            );

            try {
                return KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new ForbiddenException("Failed to generate public key for key ID: " + jsonWebKey.kid());
            }
        }

        throw new ForbiddenException("Unable to generate public key for key: " + jsonWebKey);
    }
}
