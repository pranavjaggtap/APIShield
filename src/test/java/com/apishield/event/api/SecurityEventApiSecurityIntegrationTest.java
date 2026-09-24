package com.apishield.event.api;

import com.apishield.auth.TestJwts;
import com.apishield.event.SecurityEvent;
import com.apishield.event.SecurityEventRepository;
import com.apishield.security.SecurityPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The dashboard API over real HTTP with the real Spring Security configuration: it must require a
 * valid JWT, and it must not pass through the gateway security pipeline (so reads are not themselves
 * analysed or recorded). The repository is mocked, so no PostgreSQL is needed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class SecurityEventApiSecurityIntegrationTest {

    @TestConfiguration
    static class TestJwtDecoderConfig {

        /** Stands in for the issuer/JWK configuration a real deployment provides via properties. */
        @Bean
        ReactiveJwtDecoder testJwtDecoder() {
            return TestJwts.decoder();
        }
    }

    private static final UUID EVENT_ID = UUID.fromString("00000000-0000-0000-0000-000000000042");
    private static final SecurityEvent EVENT = new SecurityEvent(EVENT_ID, "req-1",
            Instant.parse("2026-03-01T10:00:00Z"), "GET", "/api/users/1", "10.0.0.5", "user-42", "user-service",
            "BLOCK", "blocked", 0.9, 0.9, List.of("sql-injection"), List.of(true), List.of(0.9),
            List.of("matched: tautology"));

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private SecurityEventRepository repository;

    @MockitoBean
    private SecurityPipeline securityPipeline;

    @BeforeEach
    void stubRepository() {
        when(repository.findAllByOrderByOccurredAtDescIdDesc(any())).thenReturn(Flux.just(EVENT));
        when(repository.count()).thenReturn(Mono.just(1L));
        when(repository.findById(EVENT_ID)).thenReturn(Mono.just(EVENT));
    }

    @Test
    void listWithValidTokenReturnsEvents() {
        webTestClient.get().uri("/api/security/events")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("analyst-1"))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().value(HttpHeaders.CACHE_CONTROL, value -> assertThat(value).contains("no-store"))
                .expectBody()
                .jsonPath("$.content[0].id").isEqualTo(EVENT_ID.toString());

        verifyNoInteractions(securityPipeline);
    }

    @Test
    void getWithValidTokenReturnsEvent() {
        webTestClient.get().uri("/api/security/events/{id}", EVENT_ID)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("analyst-1"))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.decision").isEqualTo("BLOCK");
    }

    @Test
    void missingTokenIsRejected() {
        webTestClient.get().uri("/api/security/events")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        webTestClient.get().uri("/api/security/events/{id}", EVENT_ID)
                .exchange()
                .expectStatus().isUnauthorized();

        verify(repository, never()).findAllByOrderByOccurredAtDescIdDesc(any());
        verify(repository, never()).findById(any(UUID.class));
    }

    @Test
    void invalidAndExpiredTokensAreRejected() {
        webTestClient.get().uri("/api/security/events")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.tokenSignedByUntrustedKey("analyst-1"))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.WWW_AUTHENTICATE,
                        value -> assertThat(value).startsWith("Bearer error=\"invalid_token\""));
        webTestClient.get().uri("/api/security/events")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.expiredToken("analyst-1"))
                .exchange()
                .expectStatus().isUnauthorized();

        verify(repository, never()).findAllByOrderByOccurredAtDescIdDesc(any());
    }

    @Test
    void mutationIsNotAvailableEvenWhenAuthenticated() {
        webTestClient.post().uri("/api/security/events")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("analyst-1"))
                .exchange()
                .expectStatus().isEqualTo(405);
        webTestClient.delete().uri("/api/security/events/{id}", EVENT_ID)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("analyst-1"))
                .exchange()
                .expectStatus().isEqualTo(405);
    }
}
