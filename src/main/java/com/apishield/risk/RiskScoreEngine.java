package com.apishield.risk;

import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;

import java.util.List;

/**
 * Reduces the complete set of {@link ThreatSignal}s collected for a request into a single
 * {@link RiskScore}. Deliberately synchronous: by the time signals reach this stage, all
 * asynchronous work (detector execution) is already done, so scoring is a pure function
 * over already-available data - trivially unit-testable without a reactive test harness.
 */
public interface RiskScoreEngine {

    RiskScore score(List<ThreatSignal> signals);
}
