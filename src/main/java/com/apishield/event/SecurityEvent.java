package com.apishield.event;

import com.apishield.context.RequestContext;
import com.apishield.context.RouteInfo;
import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.IntStream;

/**
 * The persisted outcome of one request's trip through the security pipeline, stored in the
 * {@code security_events} table (see {@code db/schema.sql}).
 * <p>
 * Built only from {@link RequestContext}, {@link RiskScore} and {@link Decision} - never from the raw
 * request - so it cannot contain credentials: RequestContext already excludes the Authorization,
 * Proxy-Authorization and Cookie headers, and this event stores no headers or query parameters at all.
 * <p>
 * Threat signals are stored as four parallel PostgreSQL arrays (index {@code i} of each array belongs
 * to the same signal), which r2dbc-postgresql maps natively - no JSON codec needed. The schema
 * enforces that all four arrays have the same length.
 */
@Table("security_events")
public record SecurityEvent(
        @Id UUID id,
        String requestId,
        Instant occurredAt,
        String method,
        String path,
        String clientIp,
        String userId,
        String routeId,
        String decision,
        String decisionReason,
        double riskScore,
        double threatScore,
        List<String> signalDetectors,
        List<Boolean> signalDetected,
        List<Double> signalSeverities,
        List<String> signalDescriptions
) {

    public SecurityEvent {
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(clientIp, "clientIp");
        Objects.requireNonNull(decision, "decision");
        Objects.requireNonNull(decisionReason, "decisionReason");
        signalDetectors = List.copyOf(Objects.requireNonNull(signalDetectors, "signalDetectors"));
        signalDetected = List.copyOf(Objects.requireNonNull(signalDetected, "signalDetected"));
        signalSeverities = List.copyOf(Objects.requireNonNull(signalSeverities, "signalSeverities"));
        signalDescriptions = List.copyOf(Objects.requireNonNull(signalDescriptions, "signalDescriptions"));
        int signalCount = signalDetectors.size();
        if (signalDetected.size() != signalCount || signalSeverities.size() != signalCount
                || signalDescriptions.size() != signalCount) {
            throw new IllegalArgumentException("signal arrays must all have the same length");
        }
    }

    /**
     * A new, not-yet-persisted event ({@code id} is null; the database generates it) for a request
     * whose decision has already been made. The event time is the request's own timestamp, not the
     * time of persisting.
     */
    public static SecurityEvent create(RequestContext request, RiskScore riskScore, Decision decision) {
        List<ThreatSignal> signals = riskScore.contributingSignals();
        return new SecurityEvent(
                null,
                request.requestId(),
                request.timestamp(),
                request.method(),
                request.path(),
                request.clientIp(),
                request.userId().orElse(null),
                request.route().map(RouteInfo::routeId).orElse(null),
                decision.outcome().name(),
                decision.reason(),
                riskScore.value(),
                riskScore.threatScore(),
                signals.stream().map(ThreatSignal::detectorName).toList(),
                signals.stream().map(ThreatSignal::threatDetected).toList(),
                signals.stream().map(ThreatSignal::severity).toList(),
                signals.stream().map(ThreatSignal::description).toList());
    }

    /** The stored signals reassembled, in their stored order. */
    public List<ThreatSignal> threatSignals() {
        return IntStream.range(0, signalDetectors.size())
                .mapToObj(i -> new ThreatSignal(signalDetectors.get(i), signalDetected.get(i),
                        signalSeverities.get(i), signalDescriptions.get(i)))
                .toList();
    }
}
