package com.apishield.context;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The gateway boundary: the first APIShield filter on every routed request. Creates the request's
 * {@link RequestContext} and stores it on the exchange, then continues the chain. It makes no
 * security decision itself - later stages (currently
 * {@link com.apishield.security.SecurityGatewayFilter}) retrieve the context via
 * {@link RequestContextAttributes} and order themselves after {@link #ORDER}.
 */
@Component
public class RequestContextFilter implements GlobalFilter, Ordered {

    public static final int ORDER = Ordered.HIGHEST_PRECEDENCE;

    private final RequestContextFactory requestContextFactory;

    public RequestContextFilter(RequestContextFactory requestContextFactory) {
        this.requestContextFactory = requestContextFactory;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        RequestContextAttributes.put(exchange, requestContextFactory.create(exchange));
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
