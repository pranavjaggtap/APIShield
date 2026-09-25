package com.apishield.risk;

import com.apishield.context.RequestContext;
import com.apishield.model.RiskAdjustment;
import com.apishield.model.RiskAdjustment.Availability;
import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.RiskContext;
import com.apishield.risk.context.inputs.ClientHistory;
import com.apishield.risk.context.inputs.IdentityReputation;
import com.apishield.risk.context.inputs.RouteProfile;
import com.apishield.risk.context.inputs.ThreatHistory;
import com.apishield.risk.factor.ClientHistoryRiskFactor;
import com.apishield.risk.factor.IdentityRiskFactor;
import com.apishield.risk.factor.RiskFactor;
import com.apishield.risk.factor.RouteSensitivityRiskFactor;
import com.apishield.risk.factor.ThreatHistoryRiskFactor;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

/**
 * Contextual behavior of ContextualRiskScoreEngine (Phase 2). The Phase 1 noisy-OR behavior without
 * factors stays covered, unchanged, by ContextualRiskScoreEngineTest.
 */
class ContextualRiskScoreEngineContextTest {

    private static final double TOLERANCE = 1e-12;
    private static final RequestContext ALICE = RiskTestContexts.authenticated("alice");
    private static final ClientKey ALICE_KEY = new ClientKey(ClientKey.Kind.USER, "alice");

    private static List<RiskFactor> productionFactors() {
        return List.of(new RouteSensitivityRiskFactor(), new IdentityRiskFactor(),
                new ClientHistoryRiskFactor(), new ThreatHistoryRiskFactor());
    }

    /** As wired in production with default configuration: all four factors, priors disabled. */
    private final ContextualRiskScoreEngine engine = new ContextualRiskScoreEngine(productionFactors(), false);
    private final ContextualRiskScoreEngine engineWithPriors = new ContextualRiskScoreEngine(productionFactors(), true);
    private final ContextualRiskScoreEngine phase1 = new ContextualRiskScoreEngine();

    private static ThreatSignal threat(double severity) {
        return new ThreatSignal("detector-" + severity, true, severity, "threat");
    }

    private static ContextualInputs route(RouteProfile.Sensitivity sensitivity) {
        return ContextualInputs.builder()
                .put(RouteProfile.class, new RouteProfile(RiskTestContexts.ROUTE_ID, sensitivity)).build();
    }

    private static ContextualInputs.Builder heavyHistory() {
        return ContextualInputs.builder()
                .put(ThreatHistory.class, new ThreatHistory(ALICE_KEY, 20, Duration.ofHours(1)))
                .put(ClientHistory.class, new ClientHistory(ALICE_KEY, 20, 20, Duration.ofHours(1)));
    }

    private static RiskFactor fixedMultiplier(String name, double multiplier) {
        return new RiskFactor() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public RiskAdjustment assess(RiskContext context) {
                return RiskAdjustment.multiplier(name, multiplier, "fixed");
            }
        };
    }

    // --- Phase 1 behavior is unchanged when no contextual inputs are available -----------------

    @Test
    void withoutContextualInputsScoresAreBitIdenticalToPhase1() {
        double[] severities = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.7, 0.9, 0.95, 1.0};
        for (double a : severities) {
            for (double b : severities) {
                List<ThreatSignal> signals = List.of(threat(a), threat(b));
                RiskScore contextual = engine.score(signals, RiskContext.withoutInputs(ALICE));
                RiskScore baseline = phase1.score(signals, RiskContext.withoutInputs(ALICE));

                assertThat(contextual.value()).as("%s + %s", a, b).isEqualTo(baseline.value());
                assertThat(contextual.threatScore()).isEqualTo(baseline.threatScore());
            }
        }
    }

    @Test
    void neutralDefaultsWhenNoInputs() {
        RiskScore score = engine.score(List.of(threat(0.2)), RiskContext.withoutInputs(ALICE));

        assertThat(score.value()).isEqualTo(0.2);
        assertThat(score.contextualPrior()).isEqualTo(0.0);
        assertThat(score.contextMultiplier()).isEqualTo(1.0);
        assertThat(score.degraded()).isFalse();
        assertThat(score.adjustments()).extracting(RiskAdjustment::factor)
                .containsExactly("client-history", "identity", "route-sensitivity", "threat-history");
        assertThat(score.adjustments()).allSatisfy(adjustment -> {
            assertThat(adjustment.availability()).isEqualTo(Availability.MISSING);
            assertThat(adjustment.multiplier()).isEqualTo(1.0);
            assertThat(adjustment.prior()).isEqualTo(0.0);
        });
    }

    @Test
    void cleanRequestStaysZeroWhateverTheContext() {
        ContextualInputs everything = heavyHistory()
                .put(RouteProfile.class, new RouteProfile(RiskTestContexts.ROUTE_ID, RouteProfile.Sensitivity.CRITICAL))
                .put(IdentityReputation.class, new IdentityReputation("alice", IdentityReputation.Level.SUSPICIOUS))
                .build();

        assertThat(engine.score(List.of(), new RiskContext(ALICE, everything)).value()).isEqualTo(0.0);
    }

    // --- contextual multipliers (design worked examples) ----------------------------------------

    @Test
    void sensitiveRouteAmplifiesThreatEvidence() {
        RiskScore high = engine.score(List.of(threat(0.4)), new RiskContext(ALICE, route(RouteProfile.Sensitivity.HIGH)));
        RiskScore normal = engine.score(List.of(threat(0.4)), new RiskContext(ALICE, route(RouteProfile.Sensitivity.NORMAL)));

        assertThat(high.contextMultiplier()).isEqualTo(1.5);
        assertThat(high.value()).isCloseTo(1 - Math.pow(0.6, 1.5), within(TOLERANCE)).isCloseTo(0.5352, within(1e-4));
        assertThat(high.threatScore()).isEqualTo(0.4);
        assertThat(normal.value()).isEqualTo(0.4);
    }

    @Test
    void unauthenticatedRequestIsAmplified() {
        RiskScore anonymous = engine.score(List.of(threat(0.2)), RiskContext.withoutInputs(RiskTestContexts.anonymous()));

        assertThat(anonymous.contextMultiplier()).isEqualTo(1.2);
        assertThat(anonymous.value()).isCloseTo(1 - Math.pow(0.8, 1.2), within(TOLERANCE)).isCloseTo(0.2349, within(1e-4));
    }

    @Test
    void trustedUserIsDampenedButHighConfidenceAttackStaysHigh() {
        ContextualInputs trusted = ContextualInputs.builder()
                .put(IdentityReputation.class, new IdentityReputation("alice", IdentityReputation.Level.TRUSTED)).build();

        RiskScore score = engine.score(List.of(threat(0.9)), new RiskContext(ALICE, trusted));

        assertThat(score.contextMultiplier()).isEqualTo(0.85);
        assertThat(score.value()).isCloseTo(1 - Math.pow(0.1, 0.85), within(TOLERANCE)).isCloseTo(0.8587, within(1e-4));
        assertThat(score.value()).isGreaterThanOrEqualTo(0.5);
    }

    @Test
    void multipliersCombineAndAreClampedToTheDesignBounds() {
        ContextualInputs criticalAndSuspicious = ContextualInputs.builder()
                .put(RouteProfile.class, new RouteProfile(RiskTestContexts.ROUTE_ID, RouteProfile.Sensitivity.CRITICAL))
                .put(IdentityReputation.class, new IdentityReputation("alice", IdentityReputation.Level.SUSPICIOUS))
                .build();

        RiskScore upper = engine.score(List.of(threat(0.2)), new RiskContext(ALICE, criticalAndSuspicious));
        RiskScore lower = new ContextualRiskScoreEngine(List.of(fixedMultiplier("tiny", 0.1)), false)
                .score(List.of(threat(0.2)), RiskContext.withoutInputs(ALICE));

        assertThat(upper.contextMultiplier()).isEqualTo(ContextualRiskScoreEngine.MULTIPLIER_MAX);
        assertThat(upper.adjustments()).extracting(RiskAdjustment::multiplier).contains(2.0, 1.3);
        assertThat(lower.contextMultiplier()).isEqualTo(ContextualRiskScoreEngine.MULTIPLIER_MIN);
    }

    // --- fail-closed and bounds ------------------------------------------------------------------

    @Test
    void detectorFailureStaysExactlyOneEvenForTrustedUser() {
        ContextualInputs trusted = ContextualInputs.builder()
                .put(IdentityReputation.class, new IdentityReputation("alice", IdentityReputation.Level.TRUSTED)).build();
        ThreatSignal failure = new ThreatSignal("SqlInjectionDetector", true, 1.0, "Detector failed - failing closed");

        assertThat(engine.score(List.of(failure), new RiskContext(ALICE, trusted)).value()).isEqualTo(1.0);
    }

    @Test
    void minimumMultiplierNeverUnblocksAStrongSignal() {
        ContextualRiskScoreEngine dampening = new ContextualRiskScoreEngine(List.of(fixedMultiplier("tiny", 0.01)), false);
        // Exact bound: 1 - (1 - s)^0.8 >= 0.80  <=>  s >= 1 - 0.2^(1/0.8) = 0.86625...
        double bound = 1 - Math.pow(0.2, 1 / ContextualRiskScoreEngine.MULTIPLIER_MIN);

        assertThat(dampening.score(List.of(threat(bound + 1e-9)), RiskContext.withoutInputs(ALICE)).value())
                .isGreaterThanOrEqualTo(0.80);
        // Every current blocking detector emits at least 0.9, which stays well above the ALLOW/BLOCK threshold.
        assertThat(dampening.score(List.of(threat(0.9)), RiskContext.withoutInputs(ALICE)).value())
                .isGreaterThanOrEqualTo(0.84);
    }

    @Test
    void scoreStaysWithinUnitIntervalForAllContexts() {
        double[] severities = {0.0, 0.2, 0.5, 0.9, 1.0};
        for (RouteProfile.Sensitivity sensitivity : RouteProfile.Sensitivity.values()) {
            for (IdentityReputation.Level level : IdentityReputation.Level.values()) {
                ContextualInputs inputs = heavyHistory()
                        .put(RouteProfile.class, new RouteProfile(RiskTestContexts.ROUTE_ID, sensitivity))
                        .put(IdentityReputation.class, new IdentityReputation("alice", level))
                        .build();
                for (double severity : severities) {
                    for (ContextualRiskScoreEngine candidate : List.of(engine, engineWithPriors)) {
                        double value = candidate.score(List.of(threat(severity)), new RiskContext(ALICE, inputs)).value();
                        assertThat(value).isBetween(0.0, 1.0);
                    }
                }
            }
        }
    }

    // --- contextual priors -----------------------------------------------------------------------

    @Test
    void priorsDisabledByDefaultAreRecordedButNotApplied() {
        RiskScore score = engine.score(List.of(), new RiskContext(ALICE, heavyHistory().build()));

        assertThat(score.value()).isEqualTo(0.0);
        assertThat(score.contextualPrior()).isEqualTo(0.0);
        assertThat(score.adjustments())
                .filteredOn(adjustment -> adjustment.factor().endsWith("history"))
                .hasSize(2)
                .allSatisfy(adjustment -> {
                    assertThat(adjustment.prior()).isEqualTo(0.0);
                    assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
                    assertThat(adjustment.reason()).contains("not applied: contextual priors disabled");
                });
    }

    @Test
    void priorsDisabledNeverChangeDecisionsOnThreatRequestsEither() {
        RiskScore withHistory = engine.score(List.of(threat(0.3)), new RiskContext(ALICE, heavyHistory().build()));

        assertThat(withHistory.value()).isEqualTo(0.3);
    }

    @Test
    void priorsWhenEnabledCombineWithNoisyOrAndAreCapped() {
        ContextualInputs moderate = ContextualInputs.builder()
                .put(ThreatHistory.class, new ThreatHistory(ALICE_KEY, 5, Duration.ofHours(1)))
                .put(ClientHistory.class, new ClientHistory(ALICE_KEY, 10, 5, Duration.ofHours(1)))
                .build();

        RiskScore moderateScore = engineWithPriors.score(List.of(), new RiskContext(ALICE, moderate));
        RiskScore heavyScore = engineWithPriors.score(List.of(), new RiskContext(ALICE, heavyHistory().build()));

        double threatPrior = 0.45 * (1 - Math.exp(-1));
        assertThat(moderateScore.contextualPrior()).isCloseTo(threatPrior + 0.15 * (1 - threatPrior), within(1e-9));
        assertThat(moderateScore.value()).isEqualTo(moderateScore.contextualPrior());
        assertThat(heavyScore.contextualPrior()).isEqualTo(ContextualRiskScoreEngine.PRIOR_CAP);
    }

    @Test
    void enabledPriorsCombineWithThreatEvidence() {
        ContextualInputs fiveThreats = ContextualInputs.builder()
                .put(ThreatHistory.class, new ThreatHistory(ALICE_KEY, 5, Duration.ofHours(1))).build();

        RiskScore score = engineWithPriors.score(List.of(threat(0.2)), new RiskContext(ALICE, fiveThreats));

        double prior = 0.45 * (1 - Math.exp(-1));
        assertThat(score.value()).isCloseTo(1 - 0.8 * (1 - prior), within(1e-9)).isCloseTo(0.4276, within(1e-4));
    }

    @Test
    void contextOnlyCeilingMatchesTheDesign() {
        ContextualInputs worst = heavyHistory()
                .put(RouteProfile.class, new RouteProfile(RiskTestContexts.ROUTE_ID, RouteProfile.Sensitivity.CRITICAL))
                .put(IdentityReputation.class, new IdentityReputation("alice", IdentityReputation.Level.SUSPICIOUS))
                .build();

        // No threat signal, worst context, priors ENABLED: the capped prior (0.45) amplified by the
        // clamped multiplier (2.0) gives the design's context-only ceiling 1 - 0.55^2 = 0.6975. That is
        // below a future 0.80 BLOCK band but above today's 0.50 threshold - exactly why priors stay
        // disabled (see priorsDisabledByDefaultAreRecordedButNotApplied) until multi-tier decisions exist.
        double ceiling = engineWithPriors.score(List.of(), new RiskContext(ALICE, worst)).value();
        assertThat(ceiling).isCloseTo(0.6975, within(1e-9)).isLessThan(0.80);

        assertThat(engine.score(List.of(), new RiskContext(ALICE, worst)).value()).isEqualTo(0.0);
    }

    // --- degraded context -----------------------------------------------------------------------

    @Test
    void failedProviderMarksScoreDegradedAndIsNeutral() {
        ContextualInputs failed = ContextualInputs.builder()
                .markFailed(ThreatHistory.class).markFailed(RouteProfile.class).build();

        RiskScore score = engine.score(List.of(threat(0.4)), new RiskContext(ALICE, failed));

        assertThat(score.degraded()).isTrue();
        assertThat(score.value()).isEqualTo(0.4);
        assertThat(score.adjustments()).filteredOn(a -> a.reason().contains("provider failed")).hasSize(2)
                .allSatisfy(a -> assertThat(a.availability()).isEqualTo(Availability.MISSING));
    }

    @Test
    void throwingFactorIsTreatedAsMissingAndMarksDegraded() {
        RiskFactor broken = new RiskFactor() {
            @Override
            public String name() {
                return "broken";
            }

            @Override
            public RiskAdjustment assess(RiskContext context) {
                throw new IllegalStateException("bug");
            }
        };
        ContextualRiskScoreEngine withBroken = new ContextualRiskScoreEngine(List.of(broken), false);

        RiskScore score = withBroken.score(List.of(threat(0.9)), RiskContext.withoutInputs(ALICE));

        assertThat(score.value()).isEqualTo(0.9);
        assertThat(score.degraded()).isTrue();
        assertThat(score.adjustments()).singleElement()
                .satisfies(a -> assertThat(a.availability()).isEqualTo(Availability.MISSING));
    }

    // --- determinism and wiring ------------------------------------------------------------------

    @Test
    void factorRegistrationOrderDoesNotChangeTheResult() {
        ContextualInputs inputs = heavyHistory()
                .put(RouteProfile.class, new RouteProfile(RiskTestContexts.ROUTE_ID, RouteProfile.Sensitivity.HIGH))
                .put(IdentityReputation.class, new IdentityReputation("alice", IdentityReputation.Level.TRUSTED))
                .build();
        List<ThreatSignal> signals = List.of(threat(0.3), threat(0.45));
        RiskScore expected = engineWithPriors.score(signals, new RiskContext(ALICE, inputs));
        Random random = new Random(7);

        for (int i = 0; i < 20; i++) {
            List<RiskFactor> shuffled = new ArrayList<>(productionFactors());
            Collections.shuffle(shuffled, random);
            assertThat(new ContextualRiskScoreEngine(shuffled, true).score(signals, new RiskContext(ALICE, inputs)))
                    .isEqualTo(expected);
        }
    }

    @Test
    void duplicateFactorNamesAreRejected() {
        assertThatThrownBy(() -> new ContextualRiskScoreEngine(
                List.of(new IdentityRiskFactor(), new IdentityRiskFactor()), false))
                .isInstanceOf(IllegalStateException.class);
    }
}
