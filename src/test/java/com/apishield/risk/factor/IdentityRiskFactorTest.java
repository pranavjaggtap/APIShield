package com.apishield.risk.factor;

import com.apishield.context.RequestContext;
import com.apishield.model.RiskAdjustment;
import com.apishield.model.RiskAdjustment.Availability;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.inputs.IdentityReputation;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityRiskFactorTest {

    private final IdentityRiskFactor factor = new IdentityRiskFactor();

    private RiskAdjustment assess(RequestContext request, ContextualInputs inputs) {
        return factor.assess(RiskTestContexts.context(request, inputs));
    }

    private static ContextualInputs reputation(String userId, IdentityReputation.Level level) {
        return ContextualInputs.builder().put(IdentityReputation.class, new IdentityReputation(userId, level)).build();
    }

    @Test
    void unauthenticatedRequestIsAmplifiedAsKnownState() {
        RiskAdjustment adjustment = assess(RiskTestContexts.anonymous(), ContextualInputs.empty());

        assertThat(adjustment.multiplier()).isEqualTo(1.2);
        assertThat(adjustment.availability()).isEqualTo(Availability.APPLIED);
        assertThat(adjustment.prior()).isEqualTo(0.0);
    }

    @Test
    void authenticatedWithoutReputationIsMissingAndNeutral() {
        RiskAdjustment adjustment = assess(RiskTestContexts.authenticated("alice"), ContextualInputs.empty());

        assertThat(adjustment.multiplier()).isEqualTo(1.0);
        assertThat(adjustment.prior()).isEqualTo(0.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }

    @Test
    void trustedUserIsDampened() {
        RiskAdjustment adjustment = assess(RiskTestContexts.authenticated("alice"),
                reputation("alice", IdentityReputation.Level.TRUSTED));

        assertThat(adjustment.multiplier()).isEqualTo(0.85);
        assertThat(adjustment.availability()).isEqualTo(Availability.APPLIED);
    }

    @Test
    void suspiciousUserIsAmplified() {
        RiskAdjustment adjustment = assess(RiskTestContexts.authenticated("alice"),
                reputation("alice", IdentityReputation.Level.SUSPICIOUS));

        assertThat(adjustment.multiplier()).isEqualTo(1.3);
    }

    @Test
    void neutralReputationIsNeutral() {
        RiskAdjustment adjustment = assess(RiskTestContexts.authenticated("alice"),
                reputation("alice", IdentityReputation.Level.NEUTRAL));

        assertThat(adjustment.multiplier()).isEqualTo(1.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
    }

    @Test
    void reputationOfAnotherUserIsIgnored() {
        RiskAdjustment adjustment = assess(RiskTestContexts.authenticated("alice"),
                reputation("mallory", IdentityReputation.Level.TRUSTED));

        assertThat(adjustment.multiplier()).isEqualTo(1.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }

    @Test
    void failedReputationProviderIsMissing() {
        RiskAdjustment adjustment = assess(RiskTestContexts.authenticated("alice"),
                ContextualInputs.builder().markFailed(IdentityReputation.class).build());

        assertThat(adjustment.multiplier()).isEqualTo(1.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }
}
