package com.apishield.risk;

import com.apishield.risk.context.inputs.RouteProfile;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.Map;

/**
 * Configuration of the contextual risk engine ({@code apishield.risk.*}).
 *
 * @param contextualPriorsEnabled       whether factor-proposed priors (baseline risk from client/threat
 *                                      history) are applied. Off by default and must stay off until the
 *                                      history feedback loop is addressed (see ClientHistoryRiskFactor):
 *                                      a prior can raise risk for a request that carries no threat.
 * @param providerTimeout               how long each contextual input provider may take before its input
 *                                      is treated as missing (and the context as degraded).
 * @param routeSensitivity              gateway route id to sensitivity, e.g. {@code user-service: HIGH}.
 *                                      Routes not listed have no profile, which is neutral.
 * @param historyProvidersEnabled       whether the PostgreSQL client/threat history providers run. Off by
 *                                      default: their only effect is through priors, so while priors are
 *                                      disabled they would add database queries to every request for no
 *                                      change in any score. Enabling them does NOT enable priors.
 * @param historyWindow                 how far back client/threat history looks, from each request's timestamp.
 */
@ConfigurationProperties("apishield.risk")
public record RiskEngineProperties(
        @DefaultValue("false") boolean contextualPriorsEnabled,
        @DefaultValue("100ms") Duration providerTimeout,
        Map<String, RouteProfile.Sensitivity> routeSensitivity,
        @DefaultValue("false") boolean historyProvidersEnabled,
        @DefaultValue("1h") Duration historyWindow
) {

    public static final Duration DEFAULT_HISTORY_WINDOW = Duration.ofHours(1);

    @ConstructorBinding
    public RiskEngineProperties {
        if (providerTimeout == null || providerTimeout.isNegative() || providerTimeout.isZero()) {
            throw new IllegalArgumentException("apishield.risk.provider-timeout must be positive");
        }
        if (historyWindow == null || historyWindow.isNegative() || historyWindow.isZero()) {
            throw new IllegalArgumentException("apishield.risk.history-window must be positive");
        }
        routeSensitivity = routeSensitivity == null ? Map.of() : Map.copyOf(routeSensitivity);
    }

    /** History providers disabled, default history window. */
    public RiskEngineProperties(boolean contextualPriorsEnabled, Duration providerTimeout,
                                Map<String, RouteProfile.Sensitivity> routeSensitivity) {
        this(contextualPriorsEnabled, providerTimeout, routeSensitivity, false, DEFAULT_HISTORY_WINDOW);
    }
}
