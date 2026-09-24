package com.apishield.auth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Consumer;

/**
 * Test-only JWT issuer. Key pairs are generated in memory per test run - no key material is
 * committed, and nothing here is reachable from production configuration.
 */
final class TestJwts {

    static final KeyPair TRUSTED_KEYS = generateRsaKeyPair();
    private static final KeyPair UNTRUSTED_KEYS = generateRsaKeyPair();

    private TestJwts() {
    }

    /** A decoder that trusts only {@link #TRUSTED_KEYS}, with Spring's default validators (exp/nbf). */
    static ReactiveJwtDecoder decoder() {
        return NimbusReactiveJwtDecoder.withPublicKey((RSAPublicKey) TRUSTED_KEYS.getPublic()).build();
    }

    static String validToken(String subject) {
        Instant now = Instant.now();
        return sign(TRUSTED_KEYS, claims -> claims.subject(subject)
                .issuedAt(now.minus(Duration.ofMinutes(1)))
                .expiresAt(now.plus(Duration.ofMinutes(5))));
    }

    /** Expired well beyond Spring's default 60-second clock skew allowance. */
    static String expiredToken(String subject) {
        Instant now = Instant.now();
        return sign(TRUSTED_KEYS, claims -> claims.subject(subject)
                .issuedAt(now.minus(Duration.ofHours(2)))
                .expiresAt(now.minus(Duration.ofHours(1))));
    }

    static String tokenSignedByUntrustedKey(String subject) {
        Instant now = Instant.now();
        return sign(UNTRUSTED_KEYS, claims -> claims.subject(subject)
                .issuedAt(now)
                .expiresAt(now.plus(Duration.ofMinutes(5))));
    }

    static String tokenWithoutSubject() {
        Instant now = Instant.now();
        return sign(TRUSTED_KEYS, claims -> claims.claim("scope", "read")
                .issuedAt(now)
                .expiresAt(now.plus(Duration.ofMinutes(5))));
    }

    private static String sign(KeyPair keys, Consumer<JwtClaimsSet.Builder> claimsCustomizer) {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keys.getPublic())
                .privateKey((RSAPrivateKey) keys.getPrivate())
                .build();
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder();
        claimsCustomizer.accept(claims);
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
