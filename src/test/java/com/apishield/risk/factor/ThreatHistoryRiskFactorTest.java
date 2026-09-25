package com.apishield.risk.factor;

import com.apishield.context.RequestContext;
import com.apishield.model.RiskAdjustment;
import com.apishield.model.RiskAdjustment.Availability;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.inputs.ThreatHistory;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class ThreatHistoryRiskFactorTest {

    private static final RequestContext ALICE = RiskTestContexts.authenticated("alice");
    private static final ClientKey ALICE_KEY = new ClientKey(ClientKey.Kind.USER, "alice");

    private final ThreatHistoryRiskFactor factor = new ThreatHistoryRiskFactor();

    private RiskAdjustment assess(ThreatHistory history) {
        ContextualInputs inputs = history == null
                ? ContextualInputs.empty()
                : ContextualInputs.builder().put(ThreatHistory.class, history).build();
        return factor.assess(RiskTestContexts.context(ALICE, inputs));
    }

    private static ThreatHistory threats(long count) {
        return new ThreatHistory(ALICE_KEY, count, Duration.ofHours(1));
    }

    @Test
    void priorFollowsTheDesignFormula() {
        // 0.45 * (1 - e^(-n/5)): the design's worked example gives ~0.285 for n = 5.
        assertThat(assess(threats(5)).prior()).isCloseTo(0.45 * (1 - Math.exp(-1)), within(1e-12));
        assertThat(assess(threats(5)).prior()).isCloseTo(0.2845, within(1e-4));
        assertThat(assess(threats(1)).prior()).isCloseTo(0.45 * (1 - Math.exp(-0.2)), within(1e-12));
        assertThat(assess(threats(5)).availability()).isEqualTo(Availability.APPLIED);
        assertThat(assess(threats(5)).multiplier()).isEqualTo(1.0);
    }

    @Test
    void priorIsMonotonicAndNeverExceedsCap() {
        double previous = 0.0;
        for (long n = 1; n <= 1000; n *= 2) {
            double prior = assess(threats(n)).prior();
            assertThat(prior).isGreaterThanOrEqualTo(previous).isLessThanOrEqualTo(ThreatHistoryRiskFactor.MAX_PRIOR);
            previous = prior;
        }
    }

    @Test
    void noRecentThreatsIsNeutral() {
        RiskAdjustment adjustment = assess(threats(0));

        assertThat(adjustment.prior()).isEqualTo(0.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
    }

    @Test
    void missingHistoryIsMissingAndNeutral() {
        RiskAdjustment adjustment = assess(null);

        assertThat(adjustment.prior()).isEqualTo(0.0);
        assertThat(adjustment.multiplier()).isEqualTo(1.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }

    @Test
    void historyForAnotherClientIsIgnored() {
        RiskAdjustment adjustment = assess(new ThreatHistory(new ClientKey(ClientKey.Kind.IP, "1.2.3.4"), 50, Duration.ofHours(1)));

        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }

    @Test
    void failedProviderIsMissing() {
        RiskAdjustment adjustment = factor.assess(RiskTestContexts.context(ALICE,
                ContextualInputs.builder().markFailed(ThreatHistory.class).build()));

        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
        assertThat(adjustment.prior()).isEqualTo(0.0);
    }
}
