package com.apishield.model;

import java.util.List;

/**
 * Aggregated risk for a request, produced by {@link com.apishield.risk.RiskScoreEngine}
 * from the full set of {@link ThreatSignal}s collected for that request.
 */
public record RiskScore(double value, List<ThreatSignal> contributingSignals) {
}
