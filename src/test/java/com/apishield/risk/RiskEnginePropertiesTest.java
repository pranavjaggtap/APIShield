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
        assertThat(properties.historyProvidersEnabled()).isFalse();
        assertThat(properties.historyWindow()).isEqualTo(Duration.ofHours(1));
    }

    @Test
    void enablingHistoryProvidersLeavesPriorsDisabled() {
        RiskEngineProperties properties = bind(Map.of(
                "apishield.risk.history-providers-enabled", "true",
                "apishield.risk.history-window", "15m"));

        assertThat(properties.historyProvidersEnabled()).isTrue();
        assertThat(properties.historyWindow()).isEqualTo(Duration.ofMinutes(15));
        assertThat(properties.contextualPriorsEnabled()).isFalse();
    }

    @Test
    void rejectsNonPositiveHistoryWindow() {
        assertThatThrownBy(() -> bind(Map.of("apishield.risk.history-window", "0s")))
                .isInstanceOf(BindException.class);
    }

    @Test
    void convenienceConstructorKeepsHistoryDisabled() {
        RiskEngineProperties properties = new RiskEngineProperties(false, Duration.ofMillis(100), Map.of());

        assertThat(properties.historyProvidersEnabled()).isFalse();
        assertThat(properties.historyWindow()).isEqualTo(RiskEngineProperties.DEFAULT_HISTORY_WINDOW);
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
