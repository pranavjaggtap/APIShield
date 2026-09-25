package com.apishield.risk.context;

import com.apishield.context.RequestContext;
import com.apishield.context.RouteInfo;
import com.apishield.risk.RiskEngineProperties;
import com.apishield.risk.context.inputs.RouteProfile;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;

/**
 * Supplies {@link RouteProfile}s from configuration ({@code apishield.risk.route-sensitivity}). No I/O.
 * Empty when the request matched no route or the route has no configured sensitivity.
 */
@Component
public class ConfiguredRouteProfileProvider implements ContextualInputProvider<RouteProfile> {

    private final Map<String, RouteProfile.Sensitivity> routeSensitivity;

    public ConfiguredRouteProfileProvider(RiskEngineProperties properties) {
        this.routeSensitivity = properties.routeSensitivity();
    }

    @Override
    public Class<RouteProfile> type() {
        return RouteProfile.class;
    }

    @Override
    public Mono<RouteProfile> provide(RequestContext request) {
        return Mono.justOrEmpty(request.route()
                .map(RouteInfo::routeId)
                .flatMap(routeId -> Optional.ofNullable(routeSensitivity.get(routeId))
                        .map(sensitivity -> new RouteProfile(routeId, sensitivity))));
    }
}
