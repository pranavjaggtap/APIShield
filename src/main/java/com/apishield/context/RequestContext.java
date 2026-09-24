package com.apishield.context;

import org.springframework.util.LinkedCaseInsensitiveMap;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable snapshot of one incoming request, created once at the gateway boundary by
 * {@link RequestContextFilter} and stored on the {@code ServerWebExchange} (see
 * {@link RequestContextAttributes}) so every later stage of the request lifecycle - security
 * analysis today, authentication and event persistence later - works from the same facts.
 * <p>
 * Immutability is enforced here rather than trusted to callers: both maps are defensively copied
 * into unmodifiable structures, so a context can be shared safely across concurrently running
 * detectors. Header lookup is case-insensitive, matching HTTP semantics and the
 * {@code HttpHeaders} view detectors previously received - clients (and proxies such as Node's)
 * frequently send lower-cased names like {@code user-agent}.
 * <p>
 * {@code route} is empty when no gateway route was matched. {@code userId} is empty as created
 * by {@link RequestContextFactory}; once a request is authenticated,
 * {@link com.apishield.auth.JwtAuthenticationFilter} replaces the stored context with a copy
 * produced by {@link #withUserId(String)} - the original instance is never modified.
 */
public record RequestContext(
        String requestId,
        String method,
        String path,
        Map<String, List<String>> headers,
        Map<String, List<String>> queryParams,
        String clientIp,
        Instant timestamp,
        Optional<RouteInfo> route,
        Optional<String> userId
) {

    public RequestContext {
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(clientIp, "clientIp");
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(route, "route");
        Objects.requireNonNull(userId, "userId");
        headers = immutableCaseInsensitiveCopy(Objects.requireNonNull(headers, "headers"));
        queryParams = immutableCopy(Objects.requireNonNull(queryParams, "queryParams"));
    }

    /**
     * Returns a new context identical to this one except for the authenticated user identity.
     */
    public RequestContext withUserId(String authenticatedUserId) {
        if (authenticatedUserId == null || authenticatedUserId.isBlank()) {
            throw new IllegalArgumentException("authenticatedUserId must not be blank");
        }
        return new RequestContext(requestId, method, path, headers, queryParams, clientIp, timestamp, route,
                Optional.of(authenticatedUserId));
    }

    private static Map<String, List<String>> immutableCaseInsensitiveCopy(Map<String, List<String>> source) {
        Map<String, List<String>> copy = new LinkedCaseInsensitiveMap<>(source.size(), Locale.ROOT);
        source.forEach((name, values) -> copy.put(name, immutableValues(values)));
        return Collections.unmodifiableMap(copy);
    }

    private static Map<String, List<String>> immutableCopy(Map<String, List<String>> source) {
        Map<String, List<String>> copy = new LinkedHashMap<>();
        source.forEach((name, values) -> copy.put(name, immutableValues(values)));
        return Collections.unmodifiableMap(copy);
    }

    /**
     * Not {@code List.copyOf}: a valueless query parameter such as {@code ?flag} is represented
     * by Spring as a {@code null} value, which must be preserved rather than rejected.
     */
    private static List<String> immutableValues(List<String> values) {
        return values == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(values));
    }
}
