package com.apishield.decision;

import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultDecisionEngineTest {

    private final DefaultDecisionEngine engine = new DefaultDecisionEngine();

    @Test
    void belowThresholdAllows() {
        RiskScore riskScore = RiskScore.fromSignalsOnly(DefaultDecisionEngine.BLOCK_THRESHOLD - 0.1, List.of());

        Decision decision = engine.decide(riskScore);

        assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW);
    }

    @Test
    void atThresholdBlocks() {
        RiskScore riskScore = RiskScore.fromSignalsOnly(DefaultDecisionEngine.BLOCK_THRESHOLD, List.of());

        Decision decision = engine.decide(riskScore);

        assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK);
    }

    @Test
    void aboveThresholdBlocks() {
        RiskScore riskScore = RiskScore.fromSignalsOnly(DefaultDecisionEngine.BLOCK_THRESHOLD + 0.5, List.of());

        Decision decision = engine.decide(riskScore);

        assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK);
    }

    @Test
    void zeroScoreAllows() {
        RiskScore riskScore = RiskScore.fromSignalsOnly(0.0, List.of());

        Decision decision = engine.decide(riskScore);

        assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW);
    }
}
