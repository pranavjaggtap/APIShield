package com.apishield.risk;

import com.apishield.context.RequestContext;
import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.context.RiskContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

class ContextualRiskScoreEngineTest {

    private static final double TOLERANCE = 1e-12;

    private final ContextualRiskScoreEngine engine = new ContextualRiskScoreEngine();

    private static final RiskContext CONTEXT = RiskContext.withoutInputs(new RequestContext(
            "req-1", "GET", "/api/users/1", Map.of(), Map.of(), "127.0.0.1",
            Instant.parse("2026-01-01T00:00:00Z"), Optional.empty(), Optional.of("user-42")));

    // --- helpers -----------------------------------------------------------------------

    private static ThreatSignal threat(double severity) {
        return new ThreatSignal("detector-" + severity, true, severity, "threat");
    }

    private static ThreatSignal clean() {
        return new ThreatSignal("clean-detector", false, 0.0, "clean");
    }

    private RiskScore score(ThreatSignal... signals) {
        return engine.score(List.of(signals), CONTEXT);
    }

    // --- no threats ----------------------------------------------------------------------

    @Test
    void emptySignalsScoreZero() {
        RiskScore result = score();

        assertThat(result.value()).isEqualTo(0.0);
        assertThat(result.contributingSignals()).isEmpty();
    }

    @Test
    void cleanSignalsScoreZero() {
        ThreatSignal clean = clean();

        RiskScore result = score(clean);

        assertThat(result.value()).isEqualTo(0.0);
        assertThat(result.contributingSignals()).containsExactly(clean);
    }

    @Test
    void cleanSignalWithNonZeroSeverityIsIgnored() {
        assertThat(score(new ThreatSignal("odd-detector", false, 0.8, "clean but has severity")).value())
                .isEqualTo(0.0);
    }

    // --- single signals keep their severity exactly ---------------------------------------

    @Test
    void singleSignalOfPointTwoScoresExactlyPointTwo() {
        assertThat(score(threat(0.2)).value()).isEqualTo(0.2);
    }

    @Test
    void singleSignalOfPointFiveScoresExactlyPointFive() {
        assertThat(score(threat(0.5)).value()).isEqualTo(0.5);
    }

    @Test
    void singleSignalOfPointNineScoresExactlyPointNine() {
        assertThat(score(threat(0.9)).value()).isEqualTo(0.9);
    }

    @Test
    void singleSignalOfOneScoresExactlyOne() {
        assertThat(score(threat(1.0)).value()).isEqualTo(1.0);
    }

    @Test
    void everyCurrentDetectorSeverityIsPreservedExactly() {
        // All severities the five existing detectors can emit, plus the fail-closed 1.0.
        for (double severity : new double[]{0.2, 0.3, 0.4, 0.5, 0.7, 0.9, 0.95, 1.0}) {
            assertThat(score(threat(severity)).value()).as("severity %s", severity).isEqualTo(severity);
        }
    }

    @Test
    void cleanSignalsDoNotChangeASingleThreatsScore() {
        assertThat(score(clean(), threat(0.9), clean()).value()).isEqualTo(0.9);
    }

    // --- multiple signals use noisy-OR, not addition ----------------------------------------

    @Test
    void twoPointNineSignalsScorePointNineNine() {
        assertThat(score(threat(0.9), threat(0.9)).value()).isCloseTo(0.99, within(TOLERANCE));
    }

    @Test
    void pointThreeAndPointTwoScorePointFourFour() {
        assertThat(score(threat(0.3), threat(0.2)).value()).isCloseTo(0.44, within(TOLERANCE));
    }

    @Test
    void realisticCombinedAttackStaysBelowOne() {
        // SQLi (two categories) + XSS + curl bot signal: previously summed to 2.05.
        RiskScore result = score(threat(0.95), threat(0.9), threat(0.2));

        assertThat(result.value()).isCloseTo(0.996, within(TOLERANCE));
        assertThat(result.value()).isLessThanOrEqualTo(1.0);
    }

    @Test
    void multipleSignalsNeverScoreBelowTheirStrongestSignal() {
        assertThat(score(threat(0.2), threat(0.9), threat(0.3)).value()).isGreaterThanOrEqualTo(0.9);
    }

    // --- order independence and determinism ---------------------------------------------------

    @Test
    void signalOrderDoesNotChangeTheScore() {
        List<ThreatSignal> signals = new ArrayList<>(List.of(
                threat(0.2), threat(0.9), threat(0.3), threat(0.45), clean(), threat(0.7)));
        double expected = engine.score(signals, CONTEXT).value();
        Random random = new Random(42);

        for (int i = 0; i < 50; i++) {
            Collections.shuffle(signals, random);
            assertThat(engine.score(signals, CONTEXT).value()).isEqualTo(expected);
        }
    }

    @Test
    void sameInputsProduceIdenticalScores() {
        List<ThreatSignal> signals = List.of(threat(0.3), clean(), threat(0.6));

        assertThat(engine.score(signals, CONTEXT)).isEqualTo(engine.score(signals, CONTEXT));
    }

    // --- bounds ---------------------------------------------------------------------------------

    @Test
    void scoreAlwaysWithinUnitIntervalAcrossSeverityGrid() {
        double[] grid = {0.0, 0.01, 0.1, 0.2, 0.25, 0.3, 0.5, 0.75, 0.9, 0.99, 0.999999, 1.0};
        for (double a : grid) {
            for (double b : grid) {
                for (double c : grid) {
                    double value = score(threat(a), threat(b), threat(c)).value();
                    assertThat(value).as("%s, %s, %s", a, b, c).isBetween(0.0, 1.0);
                    assertThat(value).isGreaterThanOrEqualTo(Math.max(a, Math.max(b, c)));
                }
            }
        }
    }

    @Test
    void manyHighSignalsSaturateAtExactlyOne() {
        ThreatSignal[] signals = new ThreatSignal[200];
        for (int i = 0; i < signals.length; i++) {
            signals[i] = threat(0.99);
        }

        assertThat(score(signals).value()).isEqualTo(1.0);
    }

    @Test
    void outOfRangeSeveritiesAreClampedAndNaNFailsClosed() {
        assertThat(score(threat(1.7)).value()).isEqualTo(1.0);
        assertThat(score(threat(-0.4)).value()).isEqualTo(0.0);
        assertThat(score(threat(Double.POSITIVE_INFINITY)).value()).isEqualTo(1.0);
        assertThat(score(threat(Double.NaN)).value()).isEqualTo(1.0);
    }

    // --- fail-closed ----------------------------------------------------------------------------

    @Test
    void detectorFailureSignalAloneScoresExactlyOne() {
        // The same shape SecurityPipeline produces when a detector's Mono errors.
        ThreatSignal failure = new ThreatSignal("SqlInjectionDetector", true, 1.0, "Detector failed - failing closed: boom");

        assertThat(score(failure).value()).isEqualTo(1.0);
    }

    @Test
    void detectorFailureRemainsExactlyOneAlongsideOtherSignals() {
        ThreatSignal failure = new ThreatSignal("XssDetector", true, 1.0, "Detector failed - failing closed: boom");

        assertThat(score(threat(0.2), clean(), failure, threat(0.9)).value()).isEqualTo(1.0);
    }

    // --- context breakdown ----------------------------------------------------------------------

    @Test
    void breakdownReflectsThreatOnlyScoringForNow() {
        ThreatSignal clean = clean();
        ThreatSignal threat = threat(0.3);

        RiskScore result = engine.score(List.of(clean, threat), CONTEXT);

        assertThat(result.threatScore()).isEqualTo(result.value());
        assertThat(result.contextualPrior()).isEqualTo(0.0);
        assertThat(result.contextMultiplier()).isEqualTo(1.0);
        assertThat(result.adjustments()).isEmpty();
        assertThat(result.degraded()).isFalse();
        assertThat(result.contributingSignals()).containsExactly(clean, threat);
    }

    @Test
    void requestContextDetailsDoNotAffectTheScore() {
        RiskContext anonymousOtherRoute = RiskContext.withoutInputs(new RequestContext(
                "req-2", "POST", "/api/other", Map.of(), Map.of(), "10.0.0.9",
                Instant.parse("2030-06-01T00:00:00Z"), Optional.empty(), Optional.empty()));
        List<ThreatSignal> signals = List.of(threat(0.4), threat(0.2));

        assertThat(engine.score(signals, anonymousOtherRoute)).isEqualTo(engine.score(signals, CONTEXT));
    }

    @Test
    void rejectsNullInputs() {
        assertThatThrownBy(() -> engine.score(null, CONTEXT)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> engine.score(List.of(), null)).isInstanceOf(NullPointerException.class);
    }
}
