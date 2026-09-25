package com.apishield.decision;

import com.apishield.model.Decision;
import com.apishield.model.RiskScore;

/**
 * Turns a {@link RiskScore} into a {@link Decision} (ALLOW, MONITOR, CHALLENGE, THROTTLE or BLOCK).
 * Deliberately synchronous, same rationale as {@link com.apishield.risk.RiskScoreEngine}: pure function
 * over already-available data, independently unit-testable.
 */
public interface DecisionEngine {

    Decision decide(RiskScore riskScore);
}
