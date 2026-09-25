package com.apishield.model;

import com.apishield.model.RiskAdjustment.Availability;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RiskAdjustmentTest {

    @Test
    void missingIsNeutral() {
        RiskAdjustment adjustment = RiskAdjustment.missing("f", "no data");

        assertThat(adjustment.multiplier()).isEqualTo(1.0);
        assertThat(adjustment.prior()).isEqualTo(0.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
    }

    @Test
    void neutralHasNoEffect() {
        RiskAdjustment adjustment = RiskAdjustment.neutral("f", "nothing to do");

        assertThat(adjustment.multiplier()).isEqualTo(1.0);
        assertThat(adjustment.prior()).isEqualTo(0.0);
        assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
    }

    @Test
    void multiplierAndPriorFactoriesAreApplied() {
        assertThat(RiskAdjustment.multiplier("f", 1.5, "r"))
                .isEqualTo(new RiskAdjustment("f", 1.5, 0.0, Availability.APPLIED, "r"));
        assertThat(RiskAdjustment.prior("f", 0.2, "r"))
                .isEqualTo(new RiskAdjustment("f", 1.0, 0.2, Availability.APPLIED, "r"));
    }

    @Test
    void rejectsInvalidValues() {
        assertThatThrownBy(() -> RiskAdjustment.multiplier("f", 0.0, "r")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RiskAdjustment.prior("f", 1.5, "r")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RiskAdjustment.prior("f", Double.NaN, "r")).isInstanceOf(IllegalArgumentException.class);
    }
}
