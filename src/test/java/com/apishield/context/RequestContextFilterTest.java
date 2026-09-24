package com.apishield.context;

import com.apishield.security.SecurityGatewayFilter;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class RequestContextFilterTest {

    private final RequestContextFilter filter = new RequestContextFilter(new RequestContextFactory());

    @Test
    void storesContextOnExchangeBeforeInvokingChain() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/1").header("User-Agent", "curl/8.0").build());
        AtomicReference<RequestContext> seenByChain = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            seenByChain.set(RequestContextAttributes.get(ex).orElse(null));
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(seenByChain.get()).isNotNull();
        assertThat(seenByChain.get().path()).isEqualTo("/api/users/1");
        assertThat(seenByChain.get().headers().get("User-Agent")).containsExactly("curl/8.0");
        assertThat(RequestContextAttributes.get(exchange)).containsSame(seenByChain.get());
    }

    @Test
    void runsBeforeSecurityGatewayFilter() {
        assertThat(filter.getOrder()).isLessThan(new SecurityGatewayFilter(null).getOrder());
    }
}
