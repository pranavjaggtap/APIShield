package com.apishield.decision;

import com.apishield.model.Decision;
import com.apishield.model.Decision.Outcome;
import com.apishield.model.RiskScore;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * Five-tier threshold policy over the final risk score (always within [0,1]):
 * <pre>
 *   risk &lt; 0.25          ALLOW
 *   0.25 &lt;= risk &lt; 0.50  MONITOR
 *   0.50 &lt;= risk &lt; 0.65  CHALLENGE
 *   0.65 &lt;= risk &lt; 0.80  THROTTLE
 *   risk &gt;= 0.80         BLOCK
 * </pre>
 * Each threshold is inclusive at its lower bound, and bands are checked from BLOCK downwards, so every
 * risk value maps to exactly one outcome with no gaps or overlaps. The thresholds are exact double
 * constants compared with {@code >=} - no rounding - so e.g. {@code Math.nextDown(0.80)} is THROTTLE and
 * {@code 0.80} is BLOCK. The constants are the single source of truth, referenced by tests.
 * <p>
 * A risk value outside [0,1] or NaN cannot occur (RiskScore rejects it); if it ever did, the decision
 * fails closed to BLOCK rather than falling through to ALLOW.
 */
@Component
public class DefaultDecisionEngine implements DecisionEngine {

    public static final double MONITOR_THRESHOLD = 0.25;
    public static final double CHALLENGE_THRESHOLD = 0.50;
    public static final double THROTTLE_THRESHOLD = 0.65;
    public static final double BLOCK_THRESHOLD = 0.80;

    @Override
    public Decision decide(RiskScore riskScore) {
        double risk = riskScore.value();
        Outcome outcome = outcomeFor(risk);
        return new Decision(outcome, reason(outcome, risk));
    }

    static Outcome outcomeFor(double risk) {
        if (!(risk >= 0.0 && risk <= 1.0)) {
            return Outcome.BLOCK;
        }
        if (risk >= BLOCK_THRESHOLD) {
            return Outcome.BLOCK;
        }
        if (risk >= THROTTLE_THRESHOLD) {
            return Outcome.THROTTLE;
        }
        if (risk >= CHALLENGE_THRESHOLD) {
            return Outcome.CHALLENGE;
        }
        if (risk >= MONITOR_THRESHOLD) {
            return Outcome.MONITOR;
        }
        return Outcome.ALLOW;
    }

    /** The risk value is printed exactly (not rounded), so a value just below a threshold never reads as equal to it. */
    private static String reason(Outcome outcome, double risk) {
        return switch (outcome) {
            case ALLOW -> String.format(Locale.ROOT, "risk score %s below MONITOR threshold %.2f", risk, MONITOR_THRESHOLD);
            case MONITOR -> band(outcome, risk, MONITOR_THRESHOLD, CHALLENGE_THRESHOLD);
            case CHALLENGE -> band(outcome, risk, CHALLENGE_THRESHOLD, THROTTLE_THRESHOLD);
            case THROTTLE -> band(outcome, risk, THROTTLE_THRESHOLD, BLOCK_THRESHOLD);
            case BLOCK -> risk >= 0.0 && risk <= 1.0
                    ? String.format(Locale.ROOT, "risk score %s met or exceeded BLOCK threshold %.2f", risk, BLOCK_THRESHOLD)
                    : String.format(Locale.ROOT, "risk score %s outside [0,1] - failing closed", risk);
        };
    }

    private static String band(Outcome outcome, double risk, double lower, double upper) {
        return String.format(Locale.ROOT, "risk score %s in %s band [%.2f, %.2f)", risk, outcome, lower, upper);
    }
}
