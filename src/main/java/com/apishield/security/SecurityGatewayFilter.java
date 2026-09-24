package com.apishield.security;

import com.apishield.context.RequestContextAttributes;
import com.apishield.context.RequestContextFilter;
import com.apishield.model.Decision;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * The sole point of contact between Spring Cloud Gateway and the security pipeline.
 * Applies to every route automatically as a {@link GlobalFilter} bean - no per-route
 * configuration needed. Runs immediately after {@link RequestContextFilter} and before routing,
 * evaluating the {@link com.apishield.context.RequestContext} that filter stored on the exchange.
 * <p>
 * On BLOCK, short-circuits with 403 and never invokes the {@link GatewayFilterChain}.
 * On ALLOW, delegates to the chain for normal routing. If no RequestContext is present (a
 * filter-ordering bug), the request errors without being routed - failing closed.
 */
@Component
public class SecurityGatewayFilter implements GlobalFilter, Ordered {

    public static final int ORDER = RequestContextFilter.ORDER + 1;

    private static final byte[] BLOCK_BODY =
            "{\"error\":\"Request blocked by APIShield\"}".getBytes(StandardCharsets.UTF_8);

    private final SecurityPipeline securityPipeline;

    public SecurityGatewayFilter(SecurityPipeline securityPipeline) {
        this.securityPipeline = securityPipeline;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return Mono.fromSupplier(() -> RequestContextAttributes.require(exchange))
                .flatMap(securityPipeline::evaluate)
                .flatMap(decision -> decision.outcome() == Decision.Outcome.BLOCK
                        ? block(exchange)
                        : chain.filter(exchange));
    }

    private Mono<Void> block(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        DataBuffer buffer = response.bufferFactory().wrap(BLOCK_BODY);
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
