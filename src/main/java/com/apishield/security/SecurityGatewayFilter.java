package com.apishield.security;

import com.apishield.model.Decision;
import com.apishield.model.SecurityAnalysisContext;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * The sole point of contact between Spring Cloud Gateway and the security pipeline.
 * Applies to every route automatically as a {@link GlobalFilter} bean - no per-route
 * configuration needed. Runs before routing ({@link Ordered#HIGHEST_PRECEDENCE}).
 * <p>
 * On BLOCK, short-circuits with 403 and never invokes the {@link GatewayFilterChain}.
 * On ALLOW, delegates to the chain for normal routing.
 */
@Component
public class SecurityGatewayFilter implements GlobalFilter, Ordered {

    private static final byte[] BLOCK_BODY =
            "{\"error\":\"Request blocked by APIShield\"}".getBytes(StandardCharsets.UTF_8);

    private final SecurityPipeline securityPipeline;

    public SecurityGatewayFilter(SecurityPipeline securityPipeline) {
        this.securityPipeline = securityPipeline;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        SecurityAnalysisContext context = buildContext(exchange);
        return securityPipeline.evaluate(context)
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

    private SecurityAnalysisContext buildContext(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        String clientIp = request.getRemoteAddress() != null && request.getRemoteAddress().getAddress() != null
                ? request.getRemoteAddress().getAddress().getHostAddress()
                : "unknown";
        return new SecurityAnalysisContext(
                request.getId(),
                request.getMethod() != null ? request.getMethod().name() : "UNKNOWN",
                request.getPath().value(),
                request.getHeaders().asMultiValueMap(),
                request.getQueryParams(),
                clientIp,
                Instant.now());
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
