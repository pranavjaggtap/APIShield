package com.apishield.decision;

import com.apishield.model.Decision;
import com.apishield.model.Decision.Outcome;
import com.apishield.model.RiskScore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultDecisionEngineTest {

    private final DefaultDecisionEngine engine = new DefaultDecisionEngine();

    private Decision decide(double risk) {
        return engine.decide(RiskScore.fromSignalsOnly(risk, List.of()));
    }

    // --- exact boundaries -----------------------------------------------------------------------

    /** Math.nextDown(x) is the largest double strictly below x - the tightest possible "0.2499999...". */
    static Stream<Arguments> exactBoundaries() {
        return Stream.of(
                Arguments.of(0.00, Outcome.ALLOW),
                Arguments.of(Math.nextDown(0.25), Outcome.ALLOW),
                Arguments.of(0.25, Outcome.MONITOR),
                Arguments.of(Math.nextDown(0.50), Outcome.MONITOR),
                Arguments.of(0.50, Outcome.CHALLENGE),
                Arguments.of(Math.nextDown(0.65), Outcome.CHALLENGE),
                Arguments.of(0.65, Outcome.THROTTLE),
                Arguments.of(Math.nextDown(0.80), Outcome.THROTTLE),
                Arguments.of(0.80, Outcome.BLOCK),
                Arguments.of(1.00, Outcome.BLOCK));
    }

    @ParameterizedTest(name = "risk {0} -> {1}")
    @MethodSource("exactBoundaries")
    void exactBoundariesMapToTheirBand(double risk, Outcome expected) {
        assertThat(decide(risk).outcome()).isEqualTo(expected);
    }

    /** The same boundaries written as decimal literals, as they would appear in a spec or a log. */
    static Stream<Arguments> decimalBoundaries() {
        return Stream.of(
                Arguments.of(0.249999, Outcome.ALLOW),
                Arguments.of(0.2499999999999999, Outcome.ALLOW),
                Arguments.of(0.499999, Outcome.MONITOR),
                Arguments.of(0.4999999999999999, Outcome.MONITOR),
                Arguments.of(0.649999, Outcome.CHALLENGE),
                Arguments.of(0.6499999999999999, Outcome.CHALLENGE),
                Arguments.of(0.799999, Outcome.THROTTLE),
                Arguments.of(0.7999999999999999, Outcome.THROTTLE));
    }

    @ParameterizedTest(name = "risk {0} -> {1}")
    @MethodSource("decimalBoundaries")
    void valuesJustBelowAThresholdStayInTheLowerBand(double risk, Outcome expected) {
        assertThat(decide(risk).outcome()).isEqualTo(expected);
    }

    @Test
    void thresholdsMatchTheSpecificationAndAreStrictlyIncreasing() {
        assertThat(DefaultDecisionEngine.MONITOR_THRESHOLD).isEqualTo(0.25);
        assertThat(DefaultDecisionEngine.CHALLENGE_THRESHOLD).isEqualTo(0.50);
        assertThat(DefaultDecisionEngine.THROTTLE_THRESHOLD).isEqualTo(0.65);
        assertThat(DefaultDecisionEngine.BLOCK_THRESHOLD).isEqualTo(0.80);
        assertThat(List.of(0.0, DefaultDecisionEngine.MONITOR_THRESHOLD, DefaultDecisionEngine.CHALLENGE_THRESHOLD,
                DefaultDecisionEngine.THROTTLE_THRESHOLD, DefaultDecisionEngine.BLOCK_THRESHOLD, 1.0))
                .isSortedAccordingTo(Double::compare)
                .doesNotHaveDuplicates();
    }

    // --- whole range --------------------------------------------------------------------------------

    @Test
    void everyRiskMapsToExactlyOneOutcomeAndOutcomesNeverDecreaseAsRiskRises() {
        Set<Outcome> seen = EnumSet.noneOf(Outcome.class);
        Outcome previous = Outcome.ALLOW;
        for (int i = 0; i <= 100_000; i++) {
            double risk = i / 100_000.0;
            Outcome outcome = decide(risk).outcome();
            assertThat(outcome.ordinal()).as("risk %s", risk).isGreaterThanOrEqualTo(previous.ordinal());
            previous = outcome;
            seen.add(outcome);
        }
        assertThat(seen).containsExactlyInAnyOrder(Outcome.values());
    }

    @Test
    void sameRiskAlwaysYieldsTheSameDecision() {
        for (double risk : new double[]{0.0, 0.25, 0.5, 0.65, 0.8, 1.0, 0.3141592653589793}) {
            assertThat(decide(risk)).isEqualTo(decide(risk));
        }
    }

    @Test
    void outOfRangeOrNaNRiskFailsClosed() {
        // Unreachable through RiskScore, which rejects such values - but never fall through to ALLOW.
        assertThat(DefaultDecisionEngine.outcomeFor(Double.NaN)).isEqualTo(Outcome.BLOCK);
        assertThat(DefaultDecisionEngine.outcomeFor(-0.1)).isEqualTo(Outcome.BLOCK);
        assertThat(DefaultDecisionEngine.outcomeFor(1.1)).isEqualTo(Outcome.BLOCK);
    }

    // --- existing detector severities under the five tiers -------------------------------------

    @Test
    void currentDetectorSeveritiesMapToExpectedTiers() {
        assertThat(decide(0.2).outcome()).as("curl-like bot signal").isEqualTo(Outcome.ALLOW);
        assertThat(decide(0.3).outcome()).as("missing User-Agent only").isEqualTo(Outcome.MONITOR);
        assertThat(decide(0.5).outcome()).as("no User-Agent and no Accept headers").isEqualTo(Outcome.CHALLENGE);
        assertThat(decide(0.9).outcome()).as("SQLi / XSS / replay / frequency").isEqualTo(Outcome.BLOCK);
        assertThat(decide(1.0).outcome()).as("detector failure (fail-closed)").isEqualTo(Outcome.BLOCK);
    }

    // --- reasons ----------------------------------------------------------------------------------

    @Test
    void reasonNamesTheBandAndPrintsTheExactRisk() {
        assertThat(decide(0.1).reason()).isEqualTo("risk score 0.1 below MONITOR threshold 0.25");
        assertThat(decide(0.3).reason()).isEqualTo("risk score 0.3 in MONITOR band [0.25, 0.50)");
        assertThat(decide(0.55).reason()).isEqualTo("risk score 0.55 in CHALLENGE band [0.50, 0.65)");
        assertThat(decide(0.7).reason()).isEqualTo("risk score 0.7 in THROTTLE band [0.65, 0.80)");
        assertThat(decide(0.9).reason()).isEqualTo("risk score 0.9 met or exceeded BLOCK threshold 0.80");
    }

    @Test
    void reasonNeverRoundsAValueUpToTheThresholdItIsBelow() {
        assertThat(decide(Math.nextDown(0.80)).reason()).contains("0.7999999999999999").contains("THROTTLE");
    }

    @Test
    void reasonIsIndependentOfTheDefaultLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.GERMANY);
            assertThat(decide(0.3).reason()).isEqualTo("risk score 0.3 in MONITOR band [0.25, 0.50)");
        } finally {
            Locale.setDefault(original);
        }
    }
}
