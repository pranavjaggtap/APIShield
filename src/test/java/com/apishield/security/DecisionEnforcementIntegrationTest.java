package com.apishield.security;

import com.apishield.auth.TestJwts;
import com.apishield.model.Decision;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
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
import static org.mockito.Mockito.when;

/**
 * Five-tier enforcement over real HTTP through the whole gateway (Spring Security, JWT authentication,
 * route matching, SecurityGatewayFilter). The SecurityPipeline is mocked to return each outcome, and the
 * user-service route points at a stub that counts every request it receives - so "proceeds" means the
 * request really reached the downstream service, and BLOCK means it really did not.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DecisionEnforcementIntegrationTest {

    private static final AtomicInteger DOWNSTREAM_HITS = new AtomicInteger();
    private static final String DOWNSTREAM_BODY = "{\"source\":\"stub-user-service\"}";

    private static final DisposableServer DOWNSTREAM = HttpServer.create()
            .host("127.0.0.1")
            .port(0)
            .handle((request, response) -> {
                DOWNSTREAM_HITS.incrementAndGet();
                return response.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .sendString(Mono.just(DOWNSTREAM_BODY));
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

    @TestConfiguration
    static class TestJwtDecoderConfig {

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
    void resetDownstream() {
        DOWNSTREAM_HITS.set(0);
    }

    private WebTestClient.ResponseSpec requestDecidedAs(Decision.Outcome outcome) {
        when(securityPipeline.evaluate(any())).thenReturn(Mono.just(new Decision(outcome, "test " + outcome)));
        return webTestClient.get().uri("/api/users/1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("alice"))
                .exchange();
    }

    @ParameterizedTest(name = "{0} reaches the downstream service")
    @EnumSource(value = Decision.Outcome.class, names = {"ALLOW", "MONITOR", "CHALLENGE", "THROTTLE"})
    void nonBlockingDecisionsAreRoutedToTheDownstreamServiceUnchanged(Decision.Outcome outcome) {
        requestDecidedAs(outcome)
                .expectStatus().isOk()
                .expectHeader().doesNotExist(HttpHeaders.RETRY_AFTER)
                .expectBody(String.class).isEqualTo(DOWNSTREAM_BODY);

        assertThat(DOWNSTREAM_HITS.get()).isEqualTo(1);
    }

    @Test
    void blockReturns403AndIsNeverRouted() {
        requestDecidedAs(Decision.Outcome.BLOCK)
                .expectStatus().isForbidden()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(String.class).isEqualTo("{\"error\":\"Request blocked by APIShield\"}");

        assertThat(DOWNSTREAM_HITS.get()).isZero();
    }
}
