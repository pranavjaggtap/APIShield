package com.apishield.model;

/**
 * The verdict of a single {@link com.apishield.threat.ThreatDetector} for one request.
 * A detector always produces exactly one signal, even when clean (threatDetected=false,
 * severity=0.0), so every detector's verdict is captured, not just the ones that fire.
 */
public record ThreatSignal(
        String detectorName,
        boolean threatDetected,
        double severity,
        String description
) {
}
