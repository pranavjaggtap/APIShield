package com.apishield.risk.factor;

import com.apishield.model.RiskAdjustment;
import com.apishield.model.RiskAdjustment.Availability;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.inputs.RouteProfile;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RouteSensitivityRiskFactorTest {

    private final RouteSensitivityRiskFactor factor = new RouteSensitivityRiskFactor();

    private RiskAdjustment assess(String routeId, ContextualInputs inputs) {
        return factor.assess(RiskTestContexts.context(RiskTestContexts.request("alice", routeId), inputs));
    }

    private static ContextualInputs profile(String routeId, RouteProfile.Sensitivity sensitivity) {
        return ContextualInputs.builder().put(RouteProfile.class, new RouteProfile(routeId, sensitivity)).build();
    }

    private static void assertNeutralValues(RiskAdjustment adjustment) {
        assertThat(adjustment.multiplier()).isEqualTo(1.0);
        assertThat(adjustment.prior()).isEqualTo(0.0);
    }

    @Test
    void highAndCriticalRoutesAmplify() {
        RiskAdjustment high = assess("user-service", profile("user-service", RouteProfile.Sensitivity.HIGH));
        RiskAdjustment critical = assess("user-service", profile("user-service", RouteProfile.Sensitivity.CRITICAL));

        assertThat(high.multiplier()).isEqualTo(1.5);
        assertThat(high.availability()).isEqualTo(Availability.APPLIED);
        assertThat(critical.multiplier()).isEqualTo(2.0);
        assertThat(high.prior()).isEqualTo(0.0);
        assertThat(high.factor()).isEqualTo("route-sensitivity");
    }

    @Test
    void normalRouteIsNeutral() {
        RiskAdjustment adjustment = assess("user-service", profile("user-service", RouteProfile.Sensitivity.NORMAL));

        assertNeutralValues(adjustment);
        assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
    }

    @Test
    void unconfiguredRouteIsMissing() {
        RiskAdjustment adjustment = assess("user-service", ContextualInputs.empty());

        assertNeutralValues(adjustment);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }

    @Test
    void unroutedRequestIsMissing() {
        RiskAdjustment adjustment = assess(null, profile("user-service", RouteProfile.Sensitivity.CRITICAL));

        assertNeutralValues(adjustment);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }

    @Test
    void profileForAnotherRouteIsIgnored() {
        RiskAdjustment adjustment = assess("user-service", profile("orders-service", RouteProfile.Sensitivity.CRITICAL));

        assertNeutralValues(adjustment);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }

    @Test
    void failedProviderIsMissing() {
        RiskAdjustment adjustment = assess("user-service", ContextualInputs.builder().markFailed(RouteProfile.class).build());

        assertNeutralValues(adjustment);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
        assertThat(adjustment.reason()).contains("provider failed");
    }
}
