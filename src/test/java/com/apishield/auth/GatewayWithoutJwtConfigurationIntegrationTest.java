package com.apishield.auth;

import com.apishield.model.Decision;
import com.apishield.security.SecurityPipeline;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression test: with no JWT issuer/JWK/public key configured (the repository default, and the
 * Docker Compose setup), a routed request used to fail with HTTP 500 ("No JWT decoder configured").
 * It must be rejected with 401 instead - and never reach the security pipeline or the downstream service.
 * <p>
 * The user-service route is pointed at a stub server that counts every request it receives, and the
 * SecurityPipeline is mocked to ALLOW - so if authentication were bypassed, the request would be
 * forwarded and the stub would see it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class GatewayWithoutJwtConfigurationIntegrationTest {

    private static final AtomicInteger DOWNSTREAM_HITS = new AtomicInteger();

    private static final DisposableServer DOWNSTREAM = HttpServer.create()
            .host("127.0.0.1")
            .port(0)
            .handle((request, response) -> {
                DOWNSTREAM_HITS.incrementAndGet();
                return response.sendString(Mono.just("{\"source\":\"stub-user-service\"}"));
            })
            .bindNow();

    @DynamicPropertySource
    static void routeUserServiceToStub(DynamicPropertyRegistry registry) {
        registry.add("USER_SERVICE_HOST", () -> "127.0.0.1");
        registry.add("USER_SERVICE_PORT", DOWNSTREAM::port);
    }

    @AfterAll
    static void stopDownstream() {
        DOWNSTREAM.disposeNow();
    }

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private RouteLocator routeLocator;

    @MockitoBean
    private SecurityPipeline securityPipeline;

    @BeforeEach
    void pipelineWouldAllow() {
        DOWNSTREAM_HITS.set(0);
        when(securityPipeline.evaluate(any()))
                .thenReturn(Mono.just(new Decision(Decision.Outcome.ALLOW, "would allow if reached")));
    }

    @Test
    void userServiceRouteReallyTargetsTheStub() {
        Route route = routeLocator.getRoutes().filter(r -> r.getId().equals("user-service")).blockFirst();

        assertThat(route).isNotNull();
        assertThat(route.getUri().getPort()).isEqualTo(DOWNSTREAM.port());
    }

    @Test
    void missingAuthorizationHeaderReturns401NotServerError() {
        webTestClient.get().uri("/api/users/1")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

        assertNotRouted();
    }

    @Test
    void nonBearerAuthorizationHeaderReturns401() {
        webTestClient.get().uri("/api/users/1")
                .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

        assertNotRouted();
    }

    @Test
    void wellFormedBearerTokenCannotBeValidatedAndReturns401() {
        webTestClient.get().uri("/api/users/1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("user-42"))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.WWW_AUTHENTICATE,
                        value -> assertThat(value).startsWith("Bearer error=\"invalid_token\""));

        assertNotRouted();
    }

    @Test
    void malformedBearerTokenReturns401() {
        webTestClient.get().uri("/api/users/1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer not.a.jwt")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().value(HttpHeaders.WWW_AUTHENTICATE,
                        value -> assertThat(value).startsWith("Bearer error=\"invalid_token\""));

        assertNotRouted();
    }

    private void assertNotRouted() {
        verify(securityPipeline, never()).evaluate(any());
        assertThat(DOWNSTREAM_HITS.get()).as("requests forwarded to the downstream service").isZero();
    }
}
