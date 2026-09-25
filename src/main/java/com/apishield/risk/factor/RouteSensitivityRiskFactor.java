package com.apishield.risk.factor;

import com.apishield.context.RouteInfo;
import com.apishield.model.RiskAdjustment;
import com.apishield.risk.context.RiskContext;
import com.apishield.risk.context.inputs.RouteProfile;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Amplifies threat evidence on sensitive routes: NORMAL 1.0, HIGH 1.5, CRITICAL 2.0. Never dampens.
 * Only a multiplier - so a request with no threat evidence stays at 0 whatever the route.
 */
@Component
public class RouteSensitivityRiskFactor implements RiskFactor {

    public static final String NAME = "route-sensitivity";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public RiskAdjustment assess(RiskContext context) {
        Optional<String> routeId = context.request().route().map(RouteInfo::routeId);
        if (routeId.isEmpty()) {
            return RiskAdjustment.missing(NAME, "no gateway route matched");
        }
        if (context.inputs().failed(RouteProfile.class)) {
            return RiskAdjustment.missing(NAME, "route profile unavailable (provider failed)");
        }

        Optional<RouteProfile> profile = context.inputs().get(RouteProfile.class)
                .filter(candidate -> candidate.routeId().equals(routeId.get()));
        if (profile.isEmpty()) {
            return RiskAdjustment.missing(NAME, "no sensitivity configured for route '" + routeId.get() + "'");
        }

        RouteProfile.Sensitivity sensitivity = profile.get().sensitivity();
        if (sensitivity == RouteProfile.Sensitivity.NORMAL) {
            return RiskAdjustment.neutral(NAME, "route '" + routeId.get() + "' has NORMAL sensitivity");
        }
        return RiskAdjustment.multiplier(NAME, sensitivity.multiplier(),
                "route '" + routeId.get() + "' has " + sensitivity + " sensitivity");
    }
}
