package com.apishield.risk;

import com.apishield.risk.context.inputs.RouteProfile;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.Map;

/**
 * Configuration of the contextual risk engine ({@code apishield.risk.*}).
 *
 * @param contextualPriorsEnabled whether factor-proposed priors (baseline risk from client/threat
 *                                history) are applied. Off by default and must stay off until
 *                                multi-tier decisions exist: under the single ALLOW/BLOCK threshold a
 *                                prior could block a request that carries no threat at all.
 * @param providerTimeout         how long each contextual input provider may take before its input
 *                                is treated as missing (and the context as degraded).
 * @param routeSensitivity        gateway route id to sensitivity, e.g. {@code user-service: HIGH}.
 *                                Routes not listed have no profile, which is neutral.
 */
@ConfigurationProperties("apishield.risk")
public record RiskEngineProperties(
        @DefaultValue("false") boolean contextualPriorsEnabled,
        @DefaultValue("100ms") Duration providerTimeout,
        Map<String, RouteProfile.Sensitivity> routeSensitivity
) {

    public RiskEngineProperties {
        if (providerTimeout == null || providerTimeout.isNegative() || providerTimeout.isZero()) {
            throw new IllegalArgumentException("apishield.risk.provider-timeout must be positive");
        }
        routeSensitivity = routeSensitivity == null ? Map.of() : Map.copyOf(routeSensitivity);
    }
}
