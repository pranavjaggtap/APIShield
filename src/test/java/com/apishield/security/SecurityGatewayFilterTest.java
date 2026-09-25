package com.apishield.security;

import com.apishield.context.RequestContext;
import com.apishield.context.RequestContextAttributes;
import com.apishield.context.RequestContextFactory;
import com.apishield.model.Decision;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SecurityGatewayFilterTest {

    /** Mirrors what RequestContextFilter does earlier in the real filter chain. */
    private static MockServerWebExchange exchangeWithContext() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/1").build());
        RequestContextAttributes.put(exchange, new RequestContextFactory().create(exchange));
        return exchange;
    }

    @Test
    void allowInvokesChainAndLeavesResponseUntouched() {
        SecurityPipeline pipeline = mock(SecurityPipeline.class);
        when(pipeline.evaluate(any())).thenReturn(Mono.just(new Decision(Decision.Outcome.ALLOW, "no signals")));
        SecurityGatewayFilter filter = new SecurityGatewayFilter(pipeline);

        MockServerWebExchange exchange = exchangeWithContext();
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

        MockServerWebExchange exchange = exchangeWithContext();
        AtomicBoolean chainCalled = new AtomicBoolean(false);
        GatewayFilterChain chain = recordingChain(chainCalled);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(chainCalled.get()).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void evaluatesTheExactContextStoredOnTheExchange() {
        SecurityPipeline pipeline = mock(SecurityPipeline.class);
        when(pipeline.evaluate(any())).thenReturn(Mono.just(new Decision(Decision.Outcome.ALLOW, "no signals")));
        SecurityGatewayFilter filter = new SecurityGatewayFilter(pipeline);

        MockServerWebExchange exchange = exchangeWithContext();
        RequestContext stored = RequestContextAttributes.require(exchange);

        StepVerifier.create(filter.filter(exchange, recordingChain(new AtomicBoolean())))
                .verifyComplete();

        verify(pipeline).evaluate(same(stored));
    }

    @Test
    void missingContextFailsClosedWithoutRouting() {
        SecurityPipeline pipeline = mock(SecurityPipeline.class);
        SecurityGatewayFilter filter = new SecurityGatewayFilter(pipeline);

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/1").build());
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, recordingChain(chainCalled)))
                .expectError(IllegalStateException.class)
                .verify();

        assertThat(chainCalled.get()).isFalse();
        verify(pipeline, never()).evaluate(any());
    }

    // --- five-tier enforcement (Phase 3) ------------------------------------------------------

    private static SecurityGatewayFilter filterDeciding(Decision.Outcome outcome) {
        SecurityPipeline pipeline = mock(SecurityPipeline.class);
        when(pipeline.evaluate(any())).thenReturn(Mono.just(new Decision(outcome, "test " + outcome)));
        return new SecurityGatewayFilter(pipeline);
    }

    @ParameterizedTest(name = "{0} proceeds")
    @EnumSource(value = Decision.Outcome.class, names = {"ALLOW", "MONITOR", "CHALLENGE", "THROTTLE"})
    void nonBlockingDecisionsProceedUnchangedAndAreObservable(Decision.Outcome outcome) {
        MockServerWebExchange exchange = exchangeWithContext();
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        StepVerifier.create(filterDeciding(outcome).filter(exchange, recordingChain(chainCalled)))
                .verifyComplete();

        assertThat(chainCalled.get()).as("routed").isTrue();
        assertThat(exchange.getResponse().getStatusCode()).as("no response written by APIShield").isNull();
        assertThat(exchange.getResponse().getHeaders().isEmpty()).as("no headers added").isTrue();
        assertThat(SecurityGatewayFilter.decisionOf(exchange))
                .hasValueSatisfying(decision -> assertThat(decision.outcome()).isEqualTo(outcome));
    }

    @Test
    void blockReturnsTheExistingBlockedResponseAndIsObservable() {
        MockServerWebExchange exchange = exchangeWithContext();
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        StepVerifier.create(filterDeciding(Decision.Outcome.BLOCK).filter(exchange, recordingChain(chainCalled)))
                .verifyComplete();

        assertThat(chainCalled.get()).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(exchange.getResponse().getBodyAsString().block()).isEqualTo("{\"error\":\"Request blocked by APIShield\"}");
        assertThat(SecurityGatewayFilter.decisionOf(exchange))
                .hasValueSatisfying(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK));
    }

    @Test
    void onlyBlockStopsTheRequest() {
        for (Decision.Outcome outcome : Decision.Outcome.values()) {
            AtomicBoolean chainCalled = new AtomicBoolean(false);
            StepVerifier.create(filterDeciding(outcome).filter(exchangeWithContext(), recordingChain(chainCalled)))
                    .verifyComplete();
            assertThat(chainCalled.get()).as(outcome.name()).isEqualTo(outcome != Decision.Outcome.BLOCK);
        }
    }

    @Test
    void noDecisionIsRecordedWhenTheRequestFailsBeforeEvaluation() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/users/1").build());

        StepVerifier.create(filterDeciding(Decision.Outcome.ALLOW).filter(exchange, recordingChain(new AtomicBoolean())))
                .expectError(IllegalStateException.class)
                .verify();

        assertThat(SecurityGatewayFilter.decisionOf(exchange)).isEmpty();
    }

    private static GatewayFilterChain recordingChain(AtomicBoolean chainCalled) {
        return (ServerWebExchange ex) -> {
            chainCalled.set(true);
            return Mono.empty();
        };
    }
}
