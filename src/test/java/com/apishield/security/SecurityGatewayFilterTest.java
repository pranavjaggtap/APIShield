package com.apishield.security;

import com.apishield.model.Decision;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityGatewayFilterTest {

    @Test
    void allowInvokesChainAndLeavesResponseUntouched() {
        SecurityPipeline pipeline = mock(SecurityPipeline.class);
        when(pipeline.evaluate(any())).thenReturn(Mono.just(new Decision(Decision.Outcome.ALLOW, "no signals")));
        SecurityGatewayFilter filter = new SecurityGatewayFilter(pipeline);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/1").build());
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = recordingChain(chainCalled);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(chainCalled.get()).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void blockDoesNotInvokeChainAndReturns403() {
        SecurityPipeline pipeline = mock(SecurityPipeline.class);
        when(pipeline.evaluate(any())).thenReturn(Mono.just(new Decision(Decision.Outcome.BLOCK, "blocked")));
        SecurityGatewayFilter filter = new SecurityGatewayFilter(pipeline);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/1").build());
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = recordingChain(chainCalled);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(chainCalled.get()).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    private static GatewayFilterChain recordingChain(AtomicBoolean chainCalled) {
        return (ServerWebExchange ex) -> {
            chainCalled.set(true);
            return Mono.empty();
        };
    }
}
