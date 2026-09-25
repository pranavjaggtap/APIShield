package com.apishield.risk;

import com.apishield.risk.context.inputs.RouteProfile;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RiskEnginePropertiesTest {

    private static RiskEngineProperties bind(Map<String, String> properties) {
        return new Binder(new MapConfigurationPropertySource(properties))
                .bindOrCreate("apishield.risk", RiskEngineProperties.class);
    }

    @Test
    void defaultsAreSafe() {
        RiskEngineProperties properties = bind(Map.of());

        assertThat(properties.contextualPriorsEnabled()).isFalse();
        assertThat(properties.providerTimeout()).isEqualTo(Duration.ofMillis(100));
        assertThat(properties.routeSensitivity()).isEmpty();
    }

    @Test
    void bindsConfiguredValues() {
        RiskEngineProperties properties = bind(Map.of(
                "apishield.risk.contextual-priors-enabled", "true",
                "apishield.risk.provider-timeout", "250ms",
                "apishield.risk.route-sensitivity.user-service", "HIGH"));

        assertThat(properties.contextualPriorsEnabled()).isTrue();
        assertThat(properties.providerTimeout()).isEqualTo(Duration.ofMillis(250));
        assertThat(properties.routeSensitivity()).containsEntry("user-service", RouteProfile.Sensitivity.HIGH);
    }

    @Test
    void rejectsNonPositiveTimeout() {
        assertThatThrownBy(() -> bind(Map.of("apishield.risk.provider-timeout", "0ms")))
                .isInstanceOf(BindException.class);
    }
}
