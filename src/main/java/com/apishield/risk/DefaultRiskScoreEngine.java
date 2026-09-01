package com.apishield.risk;

import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Baseline scoring strategy for this milestone: the sum of severities of signals that
 * detected a threat. Clean signals do not contribute. Zero signals (no detectors registered,
 * or all clean) yields a score of 0.0.
 */
@Component
public class DefaultRiskScoreEngine implements RiskScoreEngine {

    @Override
    public RiskScore score(List<ThreatSignal> signals) {
        double total = signals.stream()
                .filter(ThreatSignal::threatDetected)
                .mapToDouble(ThreatSignal::severity)
                .sum();
        return new RiskScore(total, List.copyOf(signals));
    }
}
