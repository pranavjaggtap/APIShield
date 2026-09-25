package com.apishield.risk.context.history;

import com.apishield.context.RequestContext;
import com.apishield.model.RiskAdjustment;
import com.apishield.model.RiskAdjustment.Availability;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.inputs.ClientHistory;
import com.apishield.risk.factor.ClientHistoryRiskFactor;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class ClientHistoryProviderTest {

    private static final Duration WINDOW = Duration.ofHours(1);
    private static final RequestContext ALICE = RiskTestContexts.authenticated("alice");
    private static final ClientKey ALICE_KEY = new ClientKey(ClientKey.Kind.USER, "alice");

    private final ClientHistoryRiskFactor factor = new ClientHistoryRiskFactor();

    private static ClientHistory provide(ClientActivityHistory history, RequestContext request) {
        return new ClientHistoryProvider(history, WINDOW).provide(request).block(Duration.ofSeconds(5));
    }

    private RiskAdjustment assess(RequestContext request, ClientHistory history) {
        return factor.assess(RiskTestContexts.context(request,
                ContextualInputs.builder().put(ClientHistory.class, history).build()));
    }

    @Test
    void noHistoryYieldsZeroCountsWhichTheFactorTreatsAsNeutral() {
        ClientHistory history = provide(new RecordingActivityHistory(), ALICE);

        assertThat(history).isEqualTo(new ClientHistory(ALICE_KEY, 0, 0, WINDOW));
        RiskAdjustment adjustment = assess(ALICE, history);
        assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
        assertThat(adjustment.prior()).isEqualTo(0.0);
    }

    @Test
    void normalHistoryWithoutBlocksIsNeutral() {
        ClientHistory history = provide(new RecordingActivityHistory().withActivity(ALICE_KEY, 40, 0), ALICE);

        assertThat(history.requestsInWindow()).isEqualTo(40);
        assertThat(history.blockedInWindow()).isZero();
        assertThat(assess(ALICE, history).availability()).isEqualTo(Availability.NEUTRAL);
    }

    @Test
    void sufficientSampleWithBlocksProposesTheFactorsPrior() {
        ClientHistory history = provide(new RecordingActivityHistory().withActivity(ALICE_KEY, 20, 5), ALICE);

        RiskAdjustment adjustment = assess(ALICE, history);
        assertThat(adjustment.availability()).isEqualTo(Availability.APPLIED);
        assertThat(adjustment.prior()).isCloseTo(ClientHistoryRiskFactor.MAX_PRIOR * 5 / 20, within(1e-12));
    }

    @Test
    void insufficientSampleStaysNeutralEvenIfEverythingWasBlocked() {
        ClientHistory history = provide(new RecordingActivityHistory()
                .withActivity(ALICE_KEY, ClientHistoryRiskFactor.MIN_SAMPLE - 1, ClientHistoryRiskFactor.MIN_SAMPLE - 1), ALICE);

        RiskAdjustment adjustment = assess(ALICE, history);
        assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
        assertThat(adjustment.prior()).isEqualTo(0.0);
    }

    @Test
    void fullyBlockedHistoryReachesTheUnchangedMaximumPrior() {
        ClientHistory history = provide(new RecordingActivityHistory().withActivity(ALICE_KEY, 10, 10), ALICE);

        assertThat(assess(ALICE, history).prior()).isCloseTo(0.30, within(1e-12));
    }

    @Test
    void unrelatedClientsHistoryIsNotReturned() {
        RecordingActivityHistory history = new RecordingActivityHistory().withActivity(ALICE_KEY, 50, 50);
        RequestContext bob = RiskTestContexts.authenticated("bob");

        ClientHistory bobs = provide(history, bob);

        assertThat(history.lastClientKey).isEqualTo(new ClientKey(ClientKey.Kind.USER, "bob"));
        assertThat(bobs.requestsInWindow()).isZero();
        assertThat(assess(bob, bobs).prior()).isEqualTo(0.0);
    }

    @Test
    void anonymousRequestIsQueriedByClientIpNotByUser() {
        RecordingActivityHistory history = new RecordingActivityHistory();

        ClientHistory anonymous = provide(history, RiskTestContexts.anonymous());

        assertThat(history.lastClientKey).isEqualTo(new ClientKey(ClientKey.Kind.IP, RiskTestContexts.CLIENT_IP));
        assertThat(anonymous.clientKey()).isEqualTo(history.lastClientKey);
    }

    @Test
    void windowEndsAtTheRequestTimestampAndSpansTheConfiguredDuration() {
        RecordingActivityHistory history = new RecordingActivityHistory();

        provide(history, ALICE);

        assertThat(history.lastUntil).isEqualTo(ALICE.timestamp());
        assertThat(history.lastSince).isEqualTo(ALICE.timestamp().minus(WINDOW));
    }

    @Test
    void historyIsPerClientNotPerRoute() {
        // Not applicable by design: ClientHistory has no route/path dimension, so the same client on
        // a different route is asked the same question.
        RecordingActivityHistory history = new RecordingActivityHistory().withActivity(ALICE_KEY, 12, 3);

        ClientHistory onUserService = provide(history, RiskTestContexts.request("alice", "user-service"));
        ClientHistory onOtherRoute = provide(history, RiskTestContexts.request("alice", "orders-service"));

        assertThat(onOtherRoute).isEqualTo(onUserService);
    }

    @Test
    void queryErrorsPropagateForTheCollectorToTreatAsMissing() {
        ClientActivityHistory failing = new RecordingActivityHistory() {
            @Override
            public Mono<ActivityCounts> activity(ClientKey clientKey, Instant since, Instant until) {
                return Mono.error(new IllegalStateException("connection refused"));
            }
        };

        StepVerifier.create(new ClientHistoryProvider(failing, WINDOW).provide(ALICE))
                .expectError(IllegalStateException.class)
                .verify();
    }
}
