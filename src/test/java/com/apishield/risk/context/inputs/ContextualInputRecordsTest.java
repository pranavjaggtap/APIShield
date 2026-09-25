package com.apishield.risk.context.inputs;

import com.apishield.risk.context.ClientKey;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContextualInputRecordsTest {

    private static final ClientKey KEY = new ClientKey(ClientKey.Kind.USER, "alice");
    private static final Duration HOUR = Duration.ofHours(1);

    @Test
    void routeSensitivityMultipliersMatchTheDesign() {
        assertThat(RouteProfile.Sensitivity.NORMAL.multiplier()).isEqualTo(1.0);
        assertThat(RouteProfile.Sensitivity.HIGH.multiplier()).isEqualTo(1.5);
        assertThat(RouteProfile.Sensitivity.CRITICAL.multiplier()).isEqualTo(2.0);
    }

    @Test
    void reputationMultipliersMatchTheDesign() {
        assertThat(IdentityReputation.Level.TRUSTED.multiplier()).isEqualTo(0.85);
        assertThat(IdentityReputation.Level.NEUTRAL.multiplier()).isEqualTo(1.0);
        assertThat(IdentityReputation.Level.SUSPICIOUS.multiplier()).isEqualTo(1.3);
    }

    @Test
    void clientHistoryValidatesCounts() {
        assertThat(new ClientHistory(KEY, 10, 10, HOUR).blockedInWindow()).isEqualTo(10);
        assertThatThrownBy(() -> new ClientHistory(KEY, 5, 6, HOUR)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ClientHistory(KEY, -1, 0, HOUR)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ClientHistory(KEY, 1, 0, Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void threatHistoryValidatesCount() {
        assertThat(new ThreatHistory(KEY, 0, HOUR).recentThreatCount()).isZero();
        assertThatThrownBy(() -> new ThreatHistory(KEY, -1, HOUR)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ThreatHistory(KEY, 1, Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void requiredFieldsRejectNull() {
        assertThatThrownBy(() -> new RouteProfile(null, RouteProfile.Sensitivity.HIGH)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new IdentityReputation("alice", null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new ClientHistory(null, 1, 0, HOUR)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new ThreatHistory(KEY, 1, null)).isInstanceOf(NullPointerException.class);
    }
}
