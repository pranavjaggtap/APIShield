package com.apishield.event;

import com.apishield.context.RequestContext;
import com.apishield.model.Decision;
import com.apishield.model.RiskScore;

/**
 * Records the outcome of a security decision that has already been made.
 * <p>
 * Contract: must return promptly without waiting for I/O, and must never let a persistence problem
 * reach the caller. Recording is a side effect of a decision - it can neither delay nor change it.
 */
@FunctionalInterface
public interface SecurityEventRecorder {

    void record(RequestContext request, RiskScore riskScore, Decision decision);
}
