package com.apishield.risk;

import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.context.RiskContext;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Normalized risk scoring. Detected threat signals are combined with noisy-OR:
 * <pre>
 *   T = 1 - product(1 - s_i)      over calibrated severities s_i of signals with threatDetected
 * </pre>
 * i.e. the probability that at least one detector's finding is a real threat, treating detectors
 * as independent. Unlike the previous sum, T can never exceed 1.0; a single signal scores exactly
 * its own severity, so detector severities keep their existing meaning against the decision
 * threshold; and additional signals always raise the score, with diminishing effect.
 * <p>
 * Calibration currently only sanitizes severities: clamped to [0,1], with NaN treated as 1.0 so a
 * broken signal fails closed. Clean signals never contribute, whatever their severity.
 * <p>
 * Contextual inputs are not applied yet: the contextual prior is 0, the multiplier is 1, and there
 * are no adjustments, so the final value equals T. The {@link RiskContext} is accepted now so
 * context can be added without changing this engine's interface or its callers.
 * <p>
 * Pure and synchronous: no I/O, no Reactor, no clock. The same inputs always produce a bit-identical
 * score, regardless of signal order.
 */
@Component
public class ContextualRiskScoreEngine implements RiskScoreEngine {

    @Override
    public RiskScore score(List<ThreatSignal> signals, RiskContext context) {
        Objects.requireNonNull(signals, "signals");
        Objects.requireNonNull(context, "context");
        return RiskScore.fromSignalsOnly(threatScore(signals), signals);
    }

    /**
     * Computes noisy-OR as a running union, {@code T <- T + s * (1 - T)}, which is algebraically
     * identical to {@code 1 - product(1 - s_i)} but exact where it matters in floating point: the
     * first (largest) severity is taken verbatim ({@code 0 + s * 1 == s}), so a single signal equals
     * its severity and a 1.0 severity yields exactly 1.0 (every later term is multiplied by 0).
     * Folding in descending order makes the result independent of the order detectors completed in.
     */
    private static double threatScore(List<ThreatSignal> signals) {
        double[] severities = signals.stream()
                .filter(ThreatSignal::threatDetected)
                .map(signal -> calibrate(signal.severity()))
                .sorted(Comparator.reverseOrder())
                .mapToDouble(Double::doubleValue)
                .toArray();

        double threatScore = 0.0;
        for (double severity : severities) {
            threatScore = threatScore + severity * (1.0 - threatScore);
        }
        return Math.min(1.0, threatScore);
    }

    private static double calibrate(double severity) {
        if (Double.isNaN(severity)) {
            return 1.0;
        }
        return Math.max(0.0, Math.min(1.0, severity));
    }
}
