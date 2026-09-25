package com.apishield.risk.factor;

import com.apishield.model.RiskAdjustment;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.RiskContext;
import com.apishield.risk.context.inputs.ThreatHistory;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Proposes a baseline prior from a client's recent threat count, as in the contextual risk design:
 * {@code prior = 0.45 * (1 - e^(-n / 5))} - rising quickly for the first few threats and never
 * exceeding 0.45. Only applied when {@code apishield.risk.contextual-priors-enabled} is true.
 */
@Component
public class ThreatHistoryRiskFactor implements RiskFactor {

    public static final String NAME = "threat-history";
    public static final double MAX_PRIOR = 0.45;
    public static final double SATURATION_COUNT = 5.0;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public RiskAdjustment assess(RiskContext context) {
        if (context.inputs().failed(ThreatHistory.class)) {
            return RiskAdjustment.missing(NAME, "threat history unavailable (provider failed)");
        }
        ClientKey clientKey = ClientKey.of(context.request());
        Optional<ThreatHistory> history = context.inputs().get(ThreatHistory.class)
                .filter(candidate -> candidate.clientKey().equals(clientKey));
        if (history.isEmpty()) {
            return RiskAdjustment.missing(NAME, "no threat history for " + clientKey.asString());
        }

        long count = history.get().recentThreatCount();
        if (count == 0) {
            return RiskAdjustment.neutral(NAME, "no recent threats");
        }
        double prior = MAX_PRIOR * (1.0 - StrictMath.exp(-count / SATURATION_COUNT));
        return RiskAdjustment.prior(NAME, prior, count + " recent threat(s) within " + history.get().window());
    }
}
