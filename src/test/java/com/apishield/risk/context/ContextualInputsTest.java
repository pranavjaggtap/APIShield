package com.apishield.risk.context;

import com.apishield.risk.context.inputs.RouteProfile;
import com.apishield.risk.context.inputs.ThreatHistory;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContextualInputsTest {

    private static final RouteProfile PROFILE = new RouteProfile("user-service", RouteProfile.Sensitivity.HIGH);

    @Test
    void emptyHasNothingAndIsNotDegraded() {
        ContextualInputs inputs = ContextualInputs.empty();

        assertThat(inputs.isEmpty()).isTrue();
        assertThat(inputs.degraded()).isFalse();
        assertThat(inputs.get(RouteProfile.class)).isEmpty();
        assertThat(inputs.failed(RouteProfile.class)).isFalse();
    }

    @Test
    void putValueIsRetrievableByType() {
        ContextualInputs inputs = ContextualInputs.builder().put(RouteProfile.class, PROFILE).build();

        assertThat(inputs.get(RouteProfile.class)).contains(PROFILE);
        assertThat(inputs.get(ThreatHistory.class)).isEmpty();
        assertThat(inputs.degraded()).isFalse();
    }

    @Test
    void failedTypeIsMissingAndMakesContextDegraded() {
        ContextualInputs inputs = ContextualInputs.builder().markFailed(ThreatHistory.class).build();

        assertThat(inputs.get(ThreatHistory.class)).isEmpty();
        assertThat(inputs.failed(ThreatHistory.class)).isTrue();
        assertThat(inputs.failedTypes()).containsExactly(ThreatHistory.class);
        assertThat(inputs.degraded()).isTrue();
    }

    @Test
    void markFailedAfterPutRemovesTheValue() {
        ContextualInputs inputs = ContextualInputs.builder()
                .put(RouteProfile.class, PROFILE)
                .markFailed(RouteProfile.class)
                .build();

        assertThat(inputs.get(RouteProfile.class)).isEmpty();
        assertThat(inputs.failed(RouteProfile.class)).isTrue();
    }

    @Test
    void emptyBuilderYieldsTheSharedEmptyInstance() {
        assertThat(ContextualInputs.builder().build()).isSameAs(ContextualInputs.empty());
    }

    @Test
    void builtInputsAreImmutable() {
        ContextualInputs.Builder builder = ContextualInputs.builder().put(RouteProfile.class, PROFILE);
        ContextualInputs inputs = builder.build();
        builder.markFailed(RouteProfile.class);

        assertThat(inputs.get(RouteProfile.class)).contains(PROFILE);
        assertThatThrownBy(() -> inputs.failedTypes().add(RouteProfile.class))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void threatHistoryValueRoundTrips() {
        ThreatHistory history = new ThreatHistory(new ClientKey(ClientKey.Kind.USER, "alice"), 3, Duration.ofHours(1));

        assertThat(ContextualInputs.builder().put(ThreatHistory.class, history).build().get(ThreatHistory.class))
                .contains(history);
    }
}
