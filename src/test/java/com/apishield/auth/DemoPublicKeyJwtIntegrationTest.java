package com.apishield.auth;

import com.apishield.context.RequestContext;
import com.apishield.model.Decision;
import com.apishield.security.SecurityPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Proves the LOCAL DEVELOPMENT / DEMO JWT setup (docker-compose.demo.yml + scripts/demo-jwt.sh) with
 * the exact same configuration mechanism: no test decoder bean - Spring Boot's own resource-server
 * auto-configuration builds the decoder from a public-key PEM file and an audience property, and the
 * unchanged JwtAuthenticationFilter uses it.
 * <p>
 * The key pair is generated per run; only the public key is written (to a temp file), mirroring the
 * read-only public-key mount in the demo overlay. The SecurityPipeline is mocked to BLOCK, so a 403
 * proves a request passed authentication and a 401 proves it was stopped by it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DemoPublicKeyJwtIntegrationTest {

    /** Same audience as docker-compose.demo.yml and scripts/demo-jwt.sh. */
    private static final String DEMO_AUDIENCE = "apishield-demo";

    private static final KeyPair DEMO_KEYS = TestJwts.generateRsaKeyPair();
    private static final KeyPair OTHER_KEYS = TestJwts.generateRsaKeyPair();

    @DynamicPropertySource
    static void demoJwtConfiguration(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.public-key-location",
                () -> "file:" + writePublicKeyPem(DEMO_KEYS));
        registry.add("spring.security.oauth2.resourceserver.jwt.audiences", () -> DEMO_AUDIENCE);
    }

    private static Path writePublicKeyPem(KeyPair keys) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(keys.getPublic().getEncoded());
        String pem = "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
        try {
            Path file = Files.createTempFile("apishield-demo-jwt-", ".pem");
            file.toFile().deleteOnExit();
            return Files.writeString(file, pem, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String demoToken(KeyPair keys, String subject, List<String> audience, Instant expiresAt) {
        return TestJwts.sign(keys, claims -> {
            claims.issuedAt(expiresAt.minus(Duration.ofHours(2)))
                    .expiresAt(expiresAt)
                    .audience(audience);
            if (subject != null) {
                claims.subject(subject);
            }
        });
    }

    private static String validDemoToken(String subject) {
        return demoToken(DEMO_KEYS, subject, List.of(DEMO_AUDIENCE), Instant.now().plus(Duration.ofMinutes(5)));
    }

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private SecurityPipeline securityPipeline;

    @BeforeEach
    void pipelineAlwaysBlocks() {
        when(securityPipeline.evaluate(any()))
                .thenReturn(Mono.just(new Decision(Decision.Outcome.BLOCK, "test pipeline")));
    }

    private WebTestClient.ResponseSpec getUser(String authorization) {
        WebTestClient.RequestHeadersSpec<?> request = webTestClient.get().uri("/api/users/1");
        if (authorization != null) {
            request = request.header(HttpHeaders.AUTHORIZATION, authorization);
        }
        return request.exchange();
    }

    @Test
    void validDemoJwtAuthenticatesAndSubjectReachesRequestContext() {
        getUser("Bearer " + validDemoToken("alice")).expectStatus().isForbidden();

        ArgumentCaptor<RequestContext> captor = ArgumentCaptor.forClass(RequestContext.class);
        verify(securityPipeline).evaluate(captor.capture());
        assertThat(captor.getValue().userId()).contains("alice");
        assertThat(captor.getValue().headers()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
    }

    @Test
    void invalidSignatureIsRejectedWith401() {
        String signedByOtherKey = demoToken(OTHER_KEYS, "alice", List.of(DEMO_AUDIENCE),
                Instant.now().plus(Duration.ofMinutes(5)));

        getUser("Bearer " + signedByOtherKey)
                .expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.WWW_AUTHENTICATE,
                        value -> assertThat(value).startsWith("Bearer error=\"invalid_token\""));

        verify(securityPipeline, never()).evaluate(any());
    }

    @Test
    void expiredDemoJwtIsRejectedWith401() {
        String expired = demoToken(DEMO_KEYS, "alice", List.of(DEMO_AUDIENCE), Instant.now().minus(Duration.ofHours(1)));

        getUser("Bearer " + expired)
                .expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.WWW_AUTHENTICATE,
                        value -> assertThat(value).startsWith("Bearer error=\"invalid_token\""));

        verify(securityPipeline, never()).evaluate(any());
    }

    @Test
    void missingTokenIsRejectedWith401() {
        getUser(null)
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

        verify(securityPipeline, never()).evaluate(any());
    }

    @Test
    void demoKeyTokenForAnotherAudienceIsRejectedWith401() {
        String wrongAudience = demoToken(DEMO_KEYS, "alice", List.of("some-other-api"),
                Instant.now().plus(Duration.ofMinutes(5)));

        getUser("Bearer " + wrongAudience).expectStatus().isUnauthorized();

        verify(securityPipeline, never()).evaluate(any());
    }

    @Test
    void demoJwtWithoutSubjectIsRejectedWith401() {
        String noSubject = demoToken(DEMO_KEYS, null, List.of(DEMO_AUDIENCE), Instant.now().plus(Duration.ofMinutes(5)));

        getUser("Bearer " + noSubject).expectStatus().isUnauthorized();

        verify(securityPipeline, never()).evaluate(any());
    }
}
