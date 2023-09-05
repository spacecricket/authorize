package space.crickets.authorize.signing;

/**
 * Represents the JWKS response from an Oauth2 server's public-keys endpoint.
 */
public record JsonWebKey (
        /*
         * From <a href="https://tools.ietf.org/html/rfc7517">rfc7517</a>
         * <p>
         *    The "kty" (key type) parameter identifies the cryptographic algorithm
         *    family used with the key, such as "RSA" or "EC".  "kty" values should
         *    either be registered in the IANA "JSON Web Key Types" registry
         *    established by [JWA] or be a value that contains a Collision-
         *    Resistant Name.  The "kty" value is a case-sensitive string.  This
         *    member MUST be present in a JWK.
         * <p>
         *    A list of defined "kty" values can be found in the IANA "JSON Web Key
         *    Types" registry established by [JWA]; the initial contents of this
         *    registry are the values defined in Section 6.1 of [JWA].
         * <p>
         *    The key type definitions include specification of the members to be
         *    used for those key types.  Members used with specific "kty" values
         *    can be found in the IANA "JSON Web Key Parameters" registry
         *    established by Section 8.1.
         */
        String kty,

        /*
         * From <a href="https://tools.ietf.org/html/rfc7517">rfc7517</a>
         * <p>
         *    The "use" (public key use) parameter identifies the intended use of
         *    the public key.  The "use" parameter is employed to indicate whether
         *    a public key is used for encrypting data or verifying the signature
         *    on data.
         * <p>
         *    Values defined by this specification are:
         * <p>
         *    o  "sig" (signature)
         *    o  "enc" (encryption)
         * <p>
         *    Other values MAY be used.  The "use" value is a case-sensitive
         *    string.  Use of the "use" member is OPTIONAL, unless the application
         *    requires its presence.
         * <p>
         *    When a key is used to wrap another key and a public key use
         *    designation for the first key is desired, the "enc" (encryption) key
         *    use value is used, since key wrapping is a kind of encryption.  The
         *    "enc" value is also to be used for public keys used for key agreement
         *    operations.
         * <p>
         *    Additional "use" (public key use) values can be registered in the
         *    IANA "JSON Web Key Use" registry established by Section 8.2.
         *    Registering any extension values used is highly recommended when this
         *    specification is used in open environments, in which multiple
         *    organizations need to have a common understanding of any extensions
         *    used.  However, unregistered extension values can be used in closed
         *    environments, in which the producing and consuming organization will
         *    always be the same.
         */
        String use,

        /*
         * From <a href="https://tools.ietf.org/html/rfc7517">rfc7517</a>
         * <p>
         *    The "key_ops" (key operations) parameter identifies the operation(s)
         *    for which the key is intended to be used.  The "key_ops" parameter is
         *    intended for use cases in which public, private, or symmetric keys
         *    may be present.
         * <p>
         *    Its value is an array of key operation values.  Values defined by
         *    this specification are:
         * <p>
         *    o  "sign" (compute digital signature or MAC)
         *    o  "verify" (verify digital signature or MAC)
         *    o  "encrypt" (encrypt content)
         *    o  "decrypt" (decrypt content and validate decryption, if applicable)
         *    o  "wrapKey" (encrypt key)
         *    o  "unwrapKey" (decrypt key and validate decryption, if applicable)
         *    o  "deriveKey" (derive key)
         *    o  "deriveBits" (derive bits not to be used as a key)
         * <p>
         *    (Note that the "key_ops" values intentionally match the "KeyUsage"
         *    values defined in the Web Cryptography API
         *    [W3C.CR-WebCryptoAPI-20141211] specification.)
         * <p>
         *    Other values MAY be used.  The key operation values are case-
         *    sensitive strings.  Duplicate key operation values MUST NOT be
         *    present in the array.  Use of the "key_ops" member is OPTIONAL,
         *    unless the application requires its presence.
         * <p>
         *    Multiple unrelated key operations SHOULD NOT be specified for a key
         *    because of the potential vulnerabilities associated with using the
         *    same key with multiple algorithms.  Thus, the combinations "sign"
         *    with "verify", "encrypt" with "decrypt", and "wrapKey" with
         *    "unwrapKey" are permitted, but other combinations SHOULD NOT be used.
         * <p>
         *    Additional "key_ops" (key operations) values can be registered in the
         *    IANA "JSON Web Key Operations" registry established by Section 8.3.
         *    The same considerations about registering extension values apply to
         *    the "key_ops" member as do for the "use" member.
         * <p>
         *    The "use" and "key_ops" JWK members SHOULD NOT be used together;
         *    however, if both are used, the information they convey MUST be
         *    consistent.  Applications should specify which of these members they
         *    use, if either is to be used by the application.
         */
        String key_ops,

        /*
         * From <a href="https://tools.ietf.org/html/rfc7517">rfc7517</a>
         * <p>
         *    The "alg" (algorithm) parameter identifies the algorithm intended for
         *    use with the key.  The values used should either be registered in the
         *    IANA "JSON Web Signature and Encryption Algorithms" registry
         *    established by [JWA] or be a value that contains a Collision-
         *    Resistant Name.  The "alg" value is a case-sensitive ASCII string.
         *    Use of this member is OPTIONAL.
         */
        String alg,

        /*
         * From <a href="https://tools.ietf.org/html/rfc7517">rfc7517</a>
         * <p>
         *    The "kid" (key ID) parameter is used to match a specific key.  This
         *    is used, for instance, to choose among a set of keys within a JWK Set
         *    during key rollover.  The structure of the "kid" value is
         *    unspecified.  When "kid" values are used within a JWK Set, different
         *    keys within the JWK Set SHOULD use distinct "kid" values.  (One
         *    example in which different keys might use the same "kid" value is if
         *    they have different "kty" (key type) values but are considered to be
         *    equivalent alternatives by the application using them.)  The "kid"
         *    value is a case-sensitive string.  Use of this member is OPTIONAL.
         *    When used with JWS or JWE, the "kid" value is used to match a JWS or
         *    JWE "kid" Header Parameter value.
         */
        String kid,

        /*
         * From <a href="https://tools.ietf.org/html/rfc7518#section-6.3.1">rfc7518</a>
         * <p>
         *    The "e" (exponent) parameter contains the exponent value for the RSA
         *    public key.  It is represented as a Base64urlUInt-encoded value.
         * <p>
         *    For instance, when representing the value 65537, the octet sequence
         *    to be base64url-encoded MUST consist of the three octets [1, 0, 1];
         *    the resulting representation for this value is "AQAB".
         */
        String e,

        /*
         * From <a href="https://tools.ietf.org/html/rfc7518#section-6.3.1">rfc7518</a>
         * <p>
         *    The "n" (modulus) parameter contains the modulus value for the RSA
         *    public key.  It is represented as a Base64urlUInt-encoded value.
         * <p>
         *    Note that implementers have found that some cryptographic libraries
         *    prefix an extra zero-valued octet to the modulus representations they
         *    return, for instance, returning 257 octets for a 2048-bit key, rather
         *    than 256.  Implementations using such libraries will need to take
         *    care to omit the extra octet from the base64url-encoded
         */
        String n
) {
    public JsonWebKey(String keyId, String modulus) {
        this(
            "RSA",
            "sig",
            null,
            "RS256",
            keyId,
            "AQAB",
            modulus
        );
    }
}
