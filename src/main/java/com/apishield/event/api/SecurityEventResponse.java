package com.apishield.event.api;

import com.apishield.event.SecurityEvent;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Dashboard view of a persisted {@link SecurityEvent}. Signals are returned as objects rather than
 * the entity's parallel storage arrays. {@code userId} and {@code routeId} are null when absent.
 */
public record SecurityEventResponse(
        UUID id,
        String requestId,
        Instant timestamp,
        String method,
        String path,
        String clientIp,
        String userId,
        String routeId,
        String decision,
        String decisionReason,
        double riskScore,
        double threatScore,
        List<ThreatSignalResponse> threatSignals
) {

    static SecurityEventResponse from(SecurityEvent event) {
        return new SecurityEventResponse(
                event.id(),
                event.requestId(),
                event.occurredAt(),
                event.method(),
                event.path(),
                event.clientIp(),
                event.userId(),
                event.routeId(),
                event.decision(),
                event.decisionReason(),
                event.riskScore(),
                event.threatScore(),
                event.threatSignals().stream().map(ThreatSignalResponse::from).toList());
    }
}
