package com.apishield.context;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Builds a {@link RequestContext} from a {@link ServerWebExchange}. Pure, synchronous extraction
 * of data already in memory - no I/O - so it is safe to call on the reactive event loop.
 * <p>
 * Client IP is the TCP-level remote address, never {@code X-Forwarded-For}, for the same reason
 * documented on {@link com.apishield.threat.FrequencyAbuseDetector}: there is no trusted upstream
 * proxy to validate that header.
 * <p>
 * Credential-bearing headers ({@link #EXCLUDED_HEADERS}) are deliberately left out of the
 * context. No detector inspects them, and the context is intended to be logged/persisted later,
 * where raw tokens and session cookies must never end up. A future authentication layer reads
 * credentials from the request itself and records only the resulting identity.
 */
@Component
public class RequestContextFactory {

    static final Set<String> EXCLUDED_HEADERS = Set.of("authorization", "proxy-authorization", "cookie");

    private final Clock clock;

    @Autowired
    public RequestContextFactory() {
        this(Clock.systemUTC());
    }

    /**
     * Allows tests to inject a fixed clock for deterministic timestamps.
     */
    public RequestContextFactory(Clock clock) {
        this.clock = clock;
    }

    public RequestContext create(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        return new RequestContext(
                request.getId(),
                request.getMethod() != null ? request.getMethod().name() : "UNKNOWN",
                request.getPath().value(),
                securityRelevantHeaders(request),
                request.getQueryParams(),
                resolveClientIp(request),
                clock.instant(),
                resolveRoute(exchange),
                Optional.empty());
    }

    private Map<String, List<String>> securityRelevantHeaders(ServerHttpRequest request) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        request.getHeaders().forEach((name, values) -> {
            if (!EXCLUDED_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                headers.put(name, values);
            }
        });
        return headers;
    }

    private String resolveClientIp(ServerHttpRequest request) {
        return request.getRemoteAddress() != null && request.getRemoteAddress().getAddress() != null
                ? request.getRemoteAddress().getAddress().getHostAddress()
                : "unknown";
    }

    /**
     * The matched route is set by the gateway's handler mapping before any global filter runs,
     * so it is available here for every routed request.
     */
    private Optional<RouteInfo> resolveRoute(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        return Optional.ofNullable(route).map(r -> new RouteInfo(r.getId(), r.getUri()));
    }
}
