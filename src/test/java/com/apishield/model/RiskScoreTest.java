package com.apishield.model;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RiskScoreTest {

    private static final ThreatSignal SIGNAL = new ThreatSignal("detector", true, 0.4, "threat");

    @Test
    void fromSignalsOnlyUsesNeutralContext() {
        RiskScore score = RiskScore.fromSignalsOnly(0.4, List.of(SIGNAL));

        assertThat(score.value()).isEqualTo(0.4);
        assertThat(score.threatScore()).isEqualTo(0.4);
        assertThat(score.contextualPrior()).isEqualTo(RiskScore.NO_PRIOR);
        assertThat(score.contextMultiplier()).isEqualTo(RiskScore.NEUTRAL_MULTIPLIER);
        assertThat(score.contributingSignals()).containsExactly(SIGNAL);
        assertThat(score.adjustments()).isEmpty();
        assertThat(score.degraded()).isFalse();
    }

    @Test
    void acceptsUnitIntervalBoundaries() {
        assertThat(RiskScore.fromSignalsOnly(0.0, List.of()).value()).isEqualTo(0.0);
        assertThat(RiskScore.fromSignalsOnly(1.0, List.of()).value()).isEqualTo(1.0);
    }

    @Test
    void rejectsValuesOutsideUnitIntervalAndNaN() {
        for (double invalid : new double[]{-0.01, 1.01, Double.NaN, Double.POSITIVE_INFINITY}) {
            assertThatThrownBy(() -> RiskScore.fromSignalsOnly(invalid, List.of()))
                    .as("value %s", invalid)
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> new RiskScore(0.5, 0.5, 1.5, 1.0, List.of(), List.of(), false))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonPositiveOrNonFiniteMultiplier() {
        for (double invalid : new double[]{0.0, -1.0, Double.NaN, Double.POSITIVE_INFINITY}) {
            assertThatThrownBy(() -> new RiskScore(0.5, 0.5, 0.0, invalid, List.of(), List.of(), false))
                    .as("multiplier %s", invalid)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void listsAreDefensivelyCopiedAndUnmodifiable() {
        List<ThreatSignal> signals = new ArrayList<>(List.of(SIGNAL));

        RiskScore score = RiskScore.fromSignalsOnly(0.4, signals);
        signals.clear();

        assertThat(score.contributingSignals()).containsExactly(SIGNAL);
        assertThatThrownBy(() -> score.contributingSignals().add(SIGNAL))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> score.adjustments().add(null))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
