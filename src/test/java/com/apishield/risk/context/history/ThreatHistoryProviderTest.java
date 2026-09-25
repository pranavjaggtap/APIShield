package com.apishield.risk.context.history;

import com.apishield.context.RequestContext;
import com.apishield.decision.DefaultDecisionEngine;
import com.apishield.model.RiskAdjustment;
import com.apishield.model.RiskAdjustment.Availability;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.inputs.ThreatHistory;
import com.apishield.risk.factor.ThreatHistoryRiskFactor;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class ThreatHistoryProviderTest {

    private static final Duration WINDOW = Duration.ofHours(1);
    private static final RequestContext ALICE = RiskTestContexts.authenticated("alice");
    private static final ClientKey ALICE_KEY = new ClientKey(ClientKey.Kind.USER, "alice");

    private final ThreatHistoryRiskFactor factor = new ThreatHistoryRiskFactor();

    private static ThreatHistory provide(ClientActivityHistory history, RequestContext request) {
        return new ThreatHistoryProvider(history, WINDOW).provide(request).block(Duration.ofSeconds(5));
    }

    private RiskAdjustment assess(ThreatHistory history) {
        return factor.assess(RiskTestContexts.context(ALICE,
                ContextualInputs.builder().put(ThreatHistory.class, history).build()));
    }

    @Test
    void noThreatHistoryYieldsZeroWhichTheFactorTreatsAsNeutral() {
        ThreatHistory history = provide(new RecordingActivityHistory(), ALICE);

        assertThat(history).isEqualTo(new ThreatHistory(ALICE_KEY, 0, WINDOW));
        assertThat(assess(history).availability()).isEqualTo(Availability.NEUTRAL);
        assertThat(assess(history).prior()).isEqualTo(0.0);
    }

    @Test
    void threatHistoryFeedsTheUnchangedFactorFormula() {
        ThreatHistory history = provide(new RecordingActivityHistory().withThreats(ALICE_KEY, 5), ALICE);

        assertThat(history.recentThreatCount()).isEqualTo(5);
        assertThat(assess(history).prior()).isCloseTo(0.45 * (1 - Math.exp(-1)), within(1e-12));
    }

    @Test
    void threatEventsAreThoseReachingTheBlockThresholdOnDetectorEvidence() {
        RecordingActivityHistory history = new RecordingActivityHistory();

        provide(history, ALICE);

        assertThat(history.lastMinThreatScore).isEqualTo(DefaultDecisionEngine.BLOCK_THRESHOLD).isEqualTo(0.80);
    }

    @Test
    void unrelatedClientsThreatsAreNotReturned() {
        RecordingActivityHistory history = new RecordingActivityHistory().withThreats(ALICE_KEY, 50);

        ThreatHistory bobs = provide(history, RiskTestContexts.authenticated("bob"));

        assertThat(history.lastClientKey).isEqualTo(new ClientKey(ClientKey.Kind.USER, "bob"));
        assertThat(bobs.recentThreatCount()).isZero();
    }

    @Test
    void anonymousRequestIsQueriedByClientIp() {
        RecordingActivityHistory history = new RecordingActivityHistory();

        provide(history, RiskTestContexts.anonymous());

        assertThat(history.lastClientKey).isEqualTo(new ClientKey(ClientKey.Kind.IP, RiskTestContexts.CLIENT_IP));
    }

    @Test
    void windowEndsAtTheRequestTimestamp() {
        RecordingActivityHistory history = new RecordingActivityHistory();

        provide(history, ALICE);

        assertThat(history.lastUntil).isEqualTo(ALICE.timestamp());
        assertThat(history.lastSince).isEqualTo(ALICE.timestamp().minus(WINDOW));
    }

    @Test
    void historyIsPerClientNotPerPath() {
        // Not applicable by design: ThreatHistory has no path dimension.
        RecordingActivityHistory history = new RecordingActivityHistory().withThreats(ALICE_KEY, 3);

        assertThat(provide(history, RiskTestContexts.request("alice", "orders-service")))
                .isEqualTo(provide(history, RiskTestContexts.request("alice", "user-service")));
    }

    @Test
    void queryErrorsPropagateForTheCollectorToTreatAsMissing() {
        ClientActivityHistory failing = new RecordingActivityHistory() {
            @Override
            public Mono<Long> threatEventCount(ClientKey clientKey, Instant since, Instant until, double minThreatScore) {
                return Mono.error(new IllegalStateException("statement timeout"));
            }
        };

        StepVerifier.create(new ThreatHistoryProvider(failing, WINDOW).provide(ALICE))
                .expectError(IllegalStateException.class)
                .verify();
    }
}
