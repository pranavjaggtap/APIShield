package com.apishield.auth;

import com.apishield.context.RequestContext;
import com.apishield.context.RouteInfo;
import com.apishield.model.Decision;
import com.apishield.security.SecurityPipeline;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Exercises the real application wiring over HTTP: Spring Security's WebFilter chain, gateway route
 * matching, and the RequestContextFilter -> JwtAuthenticationFilter -> SecurityGatewayFilter order.
 * <p>
 * The SecurityPipeline is mocked to always BLOCK, so no downstream service, Redis, or PostgreSQL is
 * needed: a 403 proves a request passed authentication and reached the pipeline; a 401 proves it
 * was stopped before it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class AuthenticationGatewayIntegrationTest {

    @TestConfiguration
    static class TestJwtDecoderConfig {

        /** Stands in for the issuer/JWK configuration a real deployment provides via properties. */
        @Bean
        ReactiveJwtDecoder testJwtDecoder() {
            return TestJwts.decoder();
        }
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

    @Test
    void validTokenReachesPipelineWithAuthenticatedRequestContext() {
        webTestClient.get().uri("/api/users/1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("user-42"))
                .exchange()
                .expectStatus().isForbidden();

        ArgumentCaptor<RequestContext> captor = ArgumentCaptor.forClass(RequestContext.class);
        verify(securityPipeline).evaluate(captor.capture());
        RequestContext context = captor.getValue();
        assertThat(context.userId()).contains("user-42");
        assertThat(context.path()).isEqualTo("/api/users/1");
        assertThat(context.route()).map(RouteInfo::routeId).contains("user-service");
        assertThat(context.headers()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
    }

    @Test
    void missingTokenIsRejectedBeforeThePipeline() {
        webTestClient.get().uri("/api/users/1")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

        verify(securityPipeline, never()).evaluate(any());
    }

    @Test
    void invalidTokenIsRejectedBeforeThePipeline() {
        webTestClient.get().uri("/api/users/1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.tokenSignedByUntrustedKey("user-42"))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.WWW_AUTHENTICATE,
                        value -> assertThat(value).startsWith("Bearer error=\"invalid_token\""));

        verify(securityPipeline, never()).evaluate(any());
    }

    @Test
    void expiredTokenIsRejectedBeforeThePipeline() {
        webTestClient.get().uri("/api/users/1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.expiredToken("user-42"))
                .exchange()
                .expectStatus().isUnauthorized();

        verify(securityPipeline, never()).evaluate(any());
    }

    @Test
    void postWithoutCsrfTokenIsNotRejectedByDefaultSpringSecurity() {
        // Default Spring Security would reject a POST with 403 for missing CSRF token before the
        // gateway; our stateless config must let it reach JWT authentication (and here, the pipeline).
        webTestClient.post().uri("/api/users/1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("user-42"))
                .exchange()
                .expectStatus().isForbidden();

        verify(securityPipeline).evaluate(any());
    }
}
