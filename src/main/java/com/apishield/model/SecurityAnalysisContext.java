package com.apishield.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Immutable snapshot of request facts passed to every {@link com.apishield.threat.ThreatDetector}.
 * Built once per request; never mutated, since detectors may run concurrently against it.
 */
public record SecurityAnalysisContext(
        String requestId,
        String method,
        String path,
        Map<String, List<String>> headers,
        String clientIp,
        Instant timestamp
) {
}
