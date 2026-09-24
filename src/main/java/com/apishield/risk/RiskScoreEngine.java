package com.apishield.risk;

import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.context.RiskContext;

import java.util.List;

/**
 * Reduces the complete set of {@link ThreatSignal}s collected for a request, together with its
 * {@link RiskContext}, into a single {@link RiskScore} within [0,1]. Deliberately synchronous: by the
 * time signals reach this stage, all asynchronous work (detector execution, gathering contextual
 * inputs) is already done, so scoring is a pure function over already-available data - trivially
 * unit-testable without a reactive test harness.
 */
public interface RiskScoreEngine {

    RiskScore score(List<ThreatSignal> signals, RiskContext context);
}
