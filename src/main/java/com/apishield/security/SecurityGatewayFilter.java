package com.apishield.security;

import com.apishield.auth.JwtAuthenticationFilter;
import com.apishield.context.RequestContextAttributes;
import com.apishield.context.RequestContextFilter;
import com.apishield.model.Decision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.Optional;

/**
 * The sole point of contact between Spring Cloud Gateway and the security pipeline.
 * Applies to every route automatically as a {@link GlobalFilter} bean - no per-route
 * configuration needed. Runs after {@link RequestContextFilter} and {@link JwtAuthenticationFilter}
 * and before routing, evaluating the (authenticated) {@link com.apishield.context.RequestContext}
 * stored on the exchange.
 * <p>
 * What each decision does today - only BLOCK is enforced:
 * <ul>
 *   <li>ALLOW - routed normally.</li>
 *   <li>MONITOR - routed normally.</li>
 *   <li>CHALLENGE - routed normally: no challenge mechanism exists yet ({@link #challenge}).</li>
 *   <li>THROTTLE - routed normally: no throttling mechanism exists yet ({@link #throttle}).</li>
 *   <li>BLOCK - short-circuits with 403 and never invokes the {@link GatewayFilterChain}.</li>
 * </ul>
 * Every decision is observable: stored on the exchange under {@link #DECISION_ATTRIBUTE} (see
 * {@link #decisionOf}) and persisted as a security event by the {@link SecurityPipeline}. It is
 * deliberately not sent to clients, which would reveal how their requests are scored.
 * <p>
 * If no RequestContext is present (a filter-ordering bug), the request errors without being routed -
 * failing closed.
 */
@Component
public class SecurityGatewayFilter implements GlobalFilter, Ordered {

    public static final int ORDER = JwtAuthenticationFilter.ORDER + 1;

    /** Exchange attribute holding the request's {@link Decision}, for later filters and handlers. */
    public static final String DECISION_ATTRIBUTE = SecurityGatewayFilter.class.getName() + ".decision";

    private static final Logger log = LoggerFactory.getLogger(SecurityGatewayFilter.class);

    private static final byte[] BLOCK_BODY =
            "{\"error\":\"Request blocked by APIShield\"}".getBytes(StandardCharsets.UTF_8);

    private final SecurityPipeline securityPipeline;

    public SecurityGatewayFilter(SecurityPipeline securityPipeline) {
        this.securityPipeline = securityPipeline;
    }

    /** The decision made for this exchange, once the security pipeline has run. */
    public static Optional<Decision> decisionOf(ServerWebExchange exchange) {
        return Optional.ofNullable(exchange.getAttribute(DECISION_ATTRIBUTE));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return Mono.fromSupplier(() -> RequestContextAttributes.require(exchange))
                .flatMap(securityPipeline::evaluate)
                .flatMap(decision -> enforce(exchange, chain, decision));
    }

    private Mono<Void> enforce(ServerWebExchange exchange, GatewayFilterChain chain, Decision decision) {
        exchange.getAttributes().put(DECISION_ATTRIBUTE, decision);
        // Exhaustive over Decision.Outcome: adding an outcome without deciding how to enforce it fails to compile.
        return switch (decision.outcome()) {
            case ALLOW -> chain.filter(exchange);
            case MONITOR -> monitor(exchange, chain, decision);
            case CHALLENGE -> challenge(exchange, chain, decision);
            case THROTTLE -> throttle(exchange, chain, decision);
            case BLOCK -> block(exchange);
        };
    }

    /** MONITOR has no enforcement by definition: the request proceeds and the decision is recorded. */
    private Mono<Void> monitor(ServerWebExchange exchange, GatewayFilterChain chain, Decision decision) {
        if (log.isDebugEnabled()) {
            log.debug("MONITOR request {}: {}", exchange.getRequest().getId(), decision.reason());
        }
        return chain.filter(exchange);
    }

    /**
     * EXTENSION POINT - no challenge mechanism exists yet (e.g. step-up authentication, RFC 9470
     * {@code insufficient_user_authentication}). Until one is implemented here, a CHALLENGE request is
     * NOT challenged: it proceeds exactly like ALLOW, and the decision is only recorded.
     */
    private Mono<Void> challenge(ServerWebExchange exchange, GatewayFilterChain chain, Decision decision) {
        log.info("CHALLENGE not enforced (no challenge mechanism yet) - request {} proceeds: {}",
                exchange.getRequest().getId(), decision.reason());
        return chain.filter(exchange);
    }

    /**
     * EXTENSION POINT - no throttling mechanism exists yet (e.g. 429 Too Many Requests with Retry-After).
     * Until one is implemented here, a THROTTLE request is NOT throttled: it proceeds exactly like ALLOW,
     * and the decision is only recorded.
     */
    private Mono<Void> throttle(ServerWebExchange exchange, GatewayFilterChain chain, Decision decision) {
        log.info("THROTTLE not enforced (no throttling mechanism yet) - request {} proceeds: {}",
                exchange.getRequest().getId(), decision.reason());
        return chain.filter(exchange);
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
