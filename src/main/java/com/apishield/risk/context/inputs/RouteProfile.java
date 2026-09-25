package com.apishield.risk.context.inputs;

import com.apishield.risk.context.ContextualInput;

import java.util.Objects;

/**
 * How sensitive a gateway route is. Supplied from configuration
 * ({@code apishield.risk.route-sensitivity.<routeId>}) by ConfiguredRouteProfileProvider.
 */
public record RouteProfile(String routeId, Sensitivity sensitivity) implements ContextualInput {

    /** Multipliers from the contextual risk design. Routes never dampen risk, so there is no level below NORMAL. */
    public enum Sensitivity {
        NORMAL(1.0),
        HIGH(1.5),
        CRITICAL(2.0);

        private final double multiplier;

        Sensitivity(double multiplier) {
            this.multiplier = multiplier;
        }

        public double multiplier() {
            return multiplier;
        }
    }

    public RouteProfile {
        Objects.requireNonNull(routeId, "routeId");
        Objects.requireNonNull(sensitivity, "sensitivity");
    }
}
