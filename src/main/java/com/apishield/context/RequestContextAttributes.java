package com.apishield.context;

import org.springframework.web.server.ServerWebExchange;

import java.util.Optional;

/**
 * The single place that knows how a {@link RequestContext} is stored on a
 * {@link ServerWebExchange}. Exchange attributes live exactly as long as the request, and are
 * visible to every gateway filter and handler that sees the same exchange.
 */
public final class RequestContextAttributes {

    public static final String ATTRIBUTE_NAME = RequestContext.class.getName();

    private RequestContextAttributes() {
    }

    public static void put(ServerWebExchange exchange, RequestContext context) {
        exchange.getAttributes().put(ATTRIBUTE_NAME, context);
    }

    public static Optional<RequestContext> get(ServerWebExchange exchange) {
        return Optional.ofNullable(exchange.getAttribute(ATTRIBUTE_NAME));
    }

    /**
     * For stages that run after {@link RequestContextFilter} and cannot proceed without a
     * context. A missing context is a filter-ordering bug, not a client error.
     */
    public static RequestContext require(ServerWebExchange exchange) {
        return get(exchange).orElseThrow(() -> new IllegalStateException(
                "No RequestContext on exchange - RequestContextFilter must run before this stage"));
    }
}
