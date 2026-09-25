package com.apishield.risk.context;

import com.apishield.risk.RiskEngineProperties;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.inputs.RouteProfile;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.Map;

class ConfiguredRouteProfileProviderTest {

    private final ConfiguredRouteProfileProvider provider = new ConfiguredRouteProfileProvider(
            new RiskEngineProperties(false, Duration.ofMillis(100), Map.of("user-service", RouteProfile.Sensitivity.HIGH)));

    @Test
    void configuredRouteYieldsItsProfile() {
        StepVerifier.create(provider.provide(RiskTestContexts.request("alice", "user-service")))
                .expectNext(new RouteProfile("user-service", RouteProfile.Sensitivity.HIGH))
                .verifyComplete();
    }

    @Test
    void unconfiguredRouteYieldsNothing() {
        StepVerifier.create(provider.provide(RiskTestContexts.request("alice", "orders-service")))
                .verifyComplete();
    }

    @Test
    void unroutedRequestYieldsNothing() {
        StepVerifier.create(provider.provide(RiskTestContexts.request("alice", null)))
                .verifyComplete();
    }
}
