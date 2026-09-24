package com.apishield.model;

import java.util.List;
import java.util.Objects;

/**
 * Aggregated risk for a request, produced by {@link com.apishield.risk.RiskScoreEngine}, together
 * with the breakdown that explains it.
 * <ul>
 *   <li>{@code value} - the final risk, always within [0,1]; what the DecisionEngine acts on.</li>
 *   <li>{@code threatScore} - noisy-OR of the detected threat signals' severities, within [0,1].</li>
 *   <li>{@code contextualPrior} - baseline risk contributed by request context, within [0,1].</li>
 *   <li>{@code contextMultiplier} - how strongly context amplified (&gt;1) or dampened (&lt;1) the
 *       threat evidence; 1.0 is neutral.</li>
 *   <li>{@code contributingSignals} - every detector's signal for the request, clean ones included.</li>
 *   <li>{@code adjustments} - one entry per contextual risk factor that was evaluated.</li>
 *   <li>{@code degraded} - true when some contextual input was unavailable.</li>
 * </ul>
 * Out-of-range or NaN scores cannot be constructed.
 */
public record RiskScore(
        double value,
        double threatScore,
        double contextualPrior,
        double contextMultiplier,
        List<ThreatSignal> contributingSignals,
        List<RiskAdjustment> adjustments,
        boolean degraded
) {

    public static final double NO_PRIOR = 0.0;
    public static final double NEUTRAL_MULTIPLIER = 1.0;

    public RiskScore {
        requireUnitInterval("value", value);
        requireUnitInterval("threatScore", threatScore);
        requireUnitInterval("contextualPrior", contextualPrior);
        if (!Double.isFinite(contextMultiplier) || contextMultiplier <= 0.0) {
            throw new IllegalArgumentException("contextMultiplier must be finite and > 0, was " + contextMultiplier);
        }
        contributingSignals = List.copyOf(Objects.requireNonNull(contributingSignals, "contributingSignals"));
        adjustments = List.copyOf(Objects.requireNonNull(adjustments, "adjustments"));
    }

    /**
     * A score determined by threat signals alone: no contextual prior, neutral multiplier, no
     * adjustments, not degraded - so {@code value == threatScore}.
     */
    public static RiskScore fromSignalsOnly(double threatScore, List<ThreatSignal> contributingSignals) {
        return new RiskScore(threatScore, threatScore, NO_PRIOR, NEUTRAL_MULTIPLIER, contributingSignals, List.of(), false);
    }

    private static void requireUnitInterval(String name, double value) {
        // Written so NaN fails too: every comparison with NaN is false.
        if (!(value >= 0.0 && value <= 1.0)) {
            throw new IllegalArgumentException(name + " must be within [0,1], was " + value);
        }
    }
}
