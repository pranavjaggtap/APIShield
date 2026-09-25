package com.apishield.risk;

import com.apishield.model.RiskAdjustment;
import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.context.RiskContext;
import com.apishield.risk.factor.RiskFactor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Normalized contextual risk scoring:
 * <pre>
 *   T = 1 - product(1 - s_i)          noisy-OR of calibrated severities of detected threat signals
 *   P = min(PRIOR_CAP, noisy-OR(p_j)) contextual prior from factors (0 unless priors are enabled)
 *   E = 1 - (1 - T)(1 - P)            evidence
 *   M = clamp(product(m_k), MULTIPLIER_MIN, MULTIPLIER_MAX)
 *   R = 1 - (1 - E)^M                 final risk, always within [0,1]
 * </pre>
 * Detector severities keep their meaning (a single signal scores exactly its severity), multiple
 * signals raise the score with diminishing effect, and it can never exceed 1.0.
 * <p>
 * Context can only reshape evidence within bounds: a multiplier cannot create risk from nothing
 * (E = 0 gives R = 0) nor reduce certain evidence (E = 1 gives R = 1, so fail-closed detector failures
 * stay at 1.0); with {@code MULTIPLIER_MIN = 0.8} any single signal of at least 0.8663
 * ({@code 1 - 0.2^1.25}) still scores at least 0.80 - including every current 0.9+ detector severity. With neutral context (M = 1, P = 0) the result is exactly the Phase 1 threat score T.
 * <p>
 * Priors are applied only when {@code apishield.risk.contextual-priors-enabled} is true (default false):
 * under the current single ALLOW/BLOCK threshold a prior alone could block a request carrying no threat.
 * While disabled, a factor's proposed prior is not applied, and its adjustment is recorded as NEUTRAL with
 * the proposed value in its reason, so priors can be observed before being enabled.
 * <p>
 * Pure and synchronous: no I/O, no Reactor, no clock. All context was gathered beforehand into the
 * {@link RiskContext}. Factors run in name order and severities fold in descending order, so the same
 * inputs always produce a bit-identical score. A factor that throws is recorded as missing (neutral) and
 * marks the score degraded rather than failing the request.
 */
@Component
public class ContextualRiskScoreEngine implements RiskScoreEngine {

    public static final double PRIOR_CAP = 0.45;
    public static final double MULTIPLIER_MIN = 0.8;
    public static final double MULTIPLIER_MAX = 2.0;

    private final List<RiskFactor> factors;
    private final boolean contextualPriorsEnabled;

    /** No factors and priors disabled: scores are exactly the Phase 1 noisy-OR threat score. */
    public ContextualRiskScoreEngine() {
        this(List.of(), false);
    }

    @Autowired
    public ContextualRiskScoreEngine(List<RiskFactor> factors, RiskEngineProperties properties) {
        this(factors, properties.contextualPriorsEnabled());
    }

    public ContextualRiskScoreEngine(List<RiskFactor> factors, boolean contextualPriorsEnabled) {
        List<RiskFactor> sorted = new ArrayList<>(factors);
        sorted.sort(Comparator.comparing(RiskFactor::name));
        Set<String> names = new HashSet<>();
        for (RiskFactor factor : sorted) {
            if (!names.add(factor.name())) {
                throw new IllegalStateException("Duplicate risk factor name: " + factor.name());
            }
        }
        this.factors = List.copyOf(sorted);
        this.contextualPriorsEnabled = contextualPriorsEnabled;
    }

    @Override
    public RiskScore score(List<ThreatSignal> signals, RiskContext context) {
        Objects.requireNonNull(signals, "signals");
        Objects.requireNonNull(context, "context");

        double threatScore = threatScore(signals);

        List<RiskAdjustment> adjustments = new ArrayList<>(factors.size());
        boolean degraded = context.inputs().degraded();
        for (RiskFactor factor : factors) {
            RiskAdjustment adjustment = assessSafely(factor, context);
            if (adjustment == null) {
                adjustment = RiskAdjustment.missing(factor.name(), "factor failed - treated as missing");
                degraded = true;
            }
            adjustments.add(applyPriorPolicy(adjustment));
        }

        double prior = combinePriors(adjustments);
        double multiplier = combineMultipliers(adjustments);
        double evidence = union(threatScore, prior);
        double value = applyMultiplier(evidence, multiplier);

        return new RiskScore(value, threatScore, prior, multiplier, signals, adjustments, degraded);
    }

    /** Returns null if the factor throws (or returns null), so the caller can record it as missing. */
    private static RiskAdjustment assessSafely(RiskFactor factor, RiskContext context) {
        try {
            return factor.assess(context);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private RiskAdjustment applyPriorPolicy(RiskAdjustment adjustment) {
        if (contextualPriorsEnabled || adjustment.prior() == 0.0) {
            return adjustment;
        }
        RiskAdjustment.Availability availability = adjustment.multiplier() == 1.0
                ? RiskAdjustment.Availability.NEUTRAL
                : adjustment.availability();
        return new RiskAdjustment(adjustment.factor(), adjustment.multiplier(), 0.0, availability,
                adjustment.reason() + " (proposed prior %.4f not applied: contextual priors disabled)"
                        .formatted(adjustment.prior()));
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
        return noisyOr(severities);
    }

    private static double combinePriors(List<RiskAdjustment> adjustments) {
        double[] priors = adjustments.stream()
                .mapToDouble(RiskAdjustment::prior)
                .filter(prior -> prior > 0.0)
                .boxed()
                .sorted(Comparator.reverseOrder())
                .mapToDouble(Double::doubleValue)
                .toArray();
        return Math.min(PRIOR_CAP, noisyOr(priors));
    }

    /** Product in factor-name order, then clamped. Exactly 1.0 when every factor is neutral. */
    private static double combineMultipliers(List<RiskAdjustment> adjustments) {
        double product = 1.0;
        for (RiskAdjustment adjustment : adjustments) {
            product *= adjustment.multiplier();
        }
        return Math.max(MULTIPLIER_MIN, Math.min(MULTIPLIER_MAX, product));
    }

    private static double noisyOr(double[] descendingValues) {
        double result = 0.0;
        for (double value : descendingValues) {
            result = union(result, value);
        }
        return Math.min(1.0, result);
    }

    /** {@code a + b(1 - a)}: exactly {@code a} when {@code b} is 0. */
    private static double union(double a, double b) {
        return Math.min(1.0, a + b * (1.0 - a));
    }

    /** {@code 1 - (1 - E)^M}; exactly E when M is 1, so neutral context reproduces Phase 1 exactly. */
    private static double applyMultiplier(double evidence, double multiplier) {
        if (multiplier == 1.0) {
            return evidence;
        }
        double value = 1.0 - StrictMath.pow(1.0 - evidence, multiplier);
        return Math.max(0.0, Math.min(1.0, value));
    }

    private static double calibrate(double severity) {
        if (Double.isNaN(severity)) {
            return 1.0;
        }
        return Math.max(0.0, Math.min(1.0, severity));
    }
}
