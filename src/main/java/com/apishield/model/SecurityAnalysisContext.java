package com.apishield.model;

import com.apishield.context.RequestContext;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Immutable snapshot of request facts passed to every {@link com.apishield.threat.ThreatDetector}.
 * Never mutated, since detectors may run concurrently against it.
 * <p>
 * This is the detector-facing view of a request, derived from the request's {@link RequestContext}
 * via {@link #from(RequestContext)} - it is never built independently from the exchange.
 */
public record SecurityAnalysisContext(
        String requestId,
        String method,
        String path,
        Map<String, List<String>> headers,
        Map<String, List<String>> queryParams,
        String clientIp,
        Instant timestamp
) {

    public static SecurityAnalysisContext from(RequestContext context) {
        return new SecurityAnalysisContext(
                context.requestId(),
                context.method(),
                context.path(),
                context.headers(),
                context.queryParams(),
                context.clientIp(),
                context.timestamp());
    }
}
