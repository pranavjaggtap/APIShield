package com.apishield.decision;

import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import org.springframework.stereotype.Component;

/**
 * Baseline threshold-based policy for this milestone. {@link #BLOCK_THRESHOLD} is the single
 * source of truth for the cutoff - referenced here only, including by tests - and will be
 * externalized (e.g. via configuration) once the real risk engine is implemented.
 */
@Component
public class DefaultDecisionEngine implements DecisionEngine {

    public static final double BLOCK_THRESHOLD = 0.5;

    @Override
    public Decision decide(RiskScore riskScore) {
        if (riskScore.value() >= BLOCK_THRESHOLD) {
            return new Decision(Decision.Outcome.BLOCK,
                    "risk score %.2f met or exceeded block threshold %.2f".formatted(riskScore.value(), BLOCK_THRESHOLD));
        }
        return new Decision(Decision.Outcome.ALLOW,
                "risk score %.2f below block threshold %.2f".formatted(riskScore.value(), BLOCK_THRESHOLD));
    }
}
