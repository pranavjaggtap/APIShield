package com.apishield.risk;

import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultRiskScoreEngineTest {

    private final DefaultRiskScoreEngine engine = new DefaultRiskScoreEngine();

    @Test
    void zeroSignalsProduceZeroScore() {
        RiskScore result = engine.score(List.of());

        assertThat(result.value()).isEqualTo(0.0);
        assertThat(result.contributingSignals()).isEmpty();
    }

    @Test
    void cleanSignalsDoNotContributeToScore() {
        ThreatSignal clean = new ThreatSignal("detectorA", false, 0.0, "clean");

        RiskScore result = engine.score(List.of(clean));

        assertThat(result.value()).isEqualTo(0.0);
        assertThat(result.contributingSignals()).containsExactly(clean);
    }

    @Test
    void threatSignalsContributeToScore() {
        ThreatSignal threatA = new ThreatSignal("detectorA", true, 0.3, "suspicious A");
        ThreatSignal threatB = new ThreatSignal("detectorB", true, 0.4, "suspicious B");

        RiskScore result = engine.score(List.of(threatA, threatB));

        assertThat(result.value()).isEqualTo(0.7);
        assertThat(result.contributingSignals()).containsExactly(threatA, threatB);
    }

    @Test
    void mixOfCleanAndThreatSignalsOnlySumsThreats() {
        ThreatSignal clean = new ThreatSignal("detectorA", false, 0.0, "clean");
        ThreatSignal threat = new ThreatSignal("detectorB", true, 0.6, "suspicious");

        RiskScore result = engine.score(List.of(clean, threat));

        assertThat(result.value()).isEqualTo(0.6);
    }
}
