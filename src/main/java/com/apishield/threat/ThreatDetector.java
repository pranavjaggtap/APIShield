package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import reactor.core.publisher.Mono;

/**
 * A single, independently pluggable threat check. Implementations are picked up automatically
 * by Spring (via {@code List<ThreatDetector>} injection into
 * {@link com.apishield.security.SecurityPipeline}) as soon as they are registered as beans -
 * no other class needs to change.
 * <p>
 * Implementations must be fully non-blocking: this runs on the gateway's shared reactive
 * event-loop threads, so any blocking call here (a blocking HTTP client, JDBC, etc.) would
 * stall unrelated concurrent requests, not just this one.
 * <p>
 * If the returned {@code Mono} errors, {@link com.apishield.security.SecurityPipeline} treats
 * that as a fail-closed threat signal rather than silently allowing the request.
 */
public interface ThreatDetector {

    Mono<ThreatSignal> detect(SecurityAnalysisContext context);
}
