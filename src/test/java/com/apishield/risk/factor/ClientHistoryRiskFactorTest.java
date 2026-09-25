package com.apishield.risk.factor;

import com.apishield.context.RequestContext;
import com.apishield.model.RiskAdjustment;
import com.apishield.model.RiskAdjustment.Availability;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.inputs.ClientHistory;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class ClientHistoryRiskFactorTest {

    private static final RequestContext ALICE = RiskTestContexts.authenticated("alice");
    private static final ClientKey ALICE_KEY = new ClientKey(ClientKey.Kind.USER, "alice");

    private final ClientHistoryRiskFactor factor = new ClientHistoryRiskFactor();

    private RiskAdjustment assess(RequestContext request, ClientHistory history) {
        ContextualInputs inputs = history == null
                ? ContextualInputs.empty()
                : ContextualInputs.builder().put(ClientHistory.class, history).build();
        return factor.assess(RiskTestContexts.context(request, inputs));
    }

    private static ClientHistory history(ClientKey key, long requests, long blocked) {
        return new ClientHistory(key, requests, blocked, Duration.ofHours(1));
    }

    @Test
    void priorIsProportionalToBlockedShare() {
        RiskAdjustment half = assess(ALICE, history(ALICE_KEY, 20, 10));
        RiskAdjustment all = assess(ALICE, history(ALICE_KEY, 10, 10));

        assertThat(half.prior()).isCloseTo(0.15, within(1e-12));
        assertThat(all.prior()).isCloseTo(ClientHistoryRiskFactor.MAX_PRIOR, within(1e-12));
        assertThat(half.availability()).isEqualTo(Availability.APPLIED);
        assertThat(half.multiplier()).isEqualTo(1.0);
    }

    @Test
    void cleanHistoryIsNeutral() {
        RiskAdjustment adjustment = assess(ALICE, history(ALICE_KEY, 50, 0));

        assertThat(adjustment.prior()).isEqualTo(0.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
    }

    @Test
    void tooLittleHistoryIsNeutral() {
        RiskAdjustment adjustment = assess(ALICE, history(ALICE_KEY, ClientHistoryRiskFactor.MIN_SAMPLE - 1, 9));

        assertThat(adjustment.prior()).isEqualTo(0.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
    }

    @Test
    void missingHistoryIsMissingAndNeutral() {
        RiskAdjustment adjustment = assess(ALICE, null);

        assertThat(adjustment.prior()).isEqualTo(0.0);
        assertThat(adjustment.multiplier()).isEqualTo(1.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }

    @Test
    void historyForAnotherClientIsIgnored() {
        RiskAdjustment adjustment = assess(ALICE, history(new ClientKey(ClientKey.Kind.USER, "mallory"), 10, 10));

        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
        assertThat(adjustment.prior()).isEqualTo(0.0);
    }

    @Test
    void unauthenticatedClientIsMatchedByIp() {
        RiskAdjustment adjustment = assess(RiskTestContexts.anonymous(),
                history(new ClientKey(ClientKey.Kind.IP, RiskTestContexts.CLIENT_IP), 10, 5));

        assertThat(adjustment.prior()).isCloseTo(0.15, within(1e-12));
    }

    @Test
    void failedProviderIsMissing() {
        RiskAdjustment adjustment = factor.assess(RiskTestContexts.context(ALICE,
                ContextualInputs.builder().markFailed(ClientHistory.class).build()));

        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
        assertThat(adjustment.prior()).isEqualTo(0.0);
    }
}
