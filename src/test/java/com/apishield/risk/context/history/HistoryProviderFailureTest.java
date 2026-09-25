package com.apishield.risk.context.history;

import com.apishield.context.RequestContext;
import com.apishield.decision.DefaultDecisionEngine;
import com.apishield.event.PostgresClientActivityHistory;
import com.apishield.event.SecurityEventRecorder;
import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.ContextualRiskScoreEngine;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputCollector;
import com.apishield.risk.context.ContextualInputProvider;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.inputs.ClientHistory;
import com.apishield.risk.context.inputs.ThreatHistory;
import com.apishield.risk.factor.ClientHistoryRiskFactor;
import com.apishield.risk.factor.IdentityRiskFactor;
import com.apishield.risk.factor.RouteSensitivityRiskFactor;
import com.apishield.risk.factor.ThreatHistoryRiskFactor;
import com.apishield.security.SecurityPipeline;
import com.apishield.threat.ThreatDetector;
import io.r2dbc.spi.ConnectionFactories;
import org.junit.jupiter.api.Test;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * History providers failing in every way the request path can see - database unreachable (a real
 * PostgreSQL driver against a closed port), timeout, malformed result - must leave the inputs MISSING
 * and the context degraded, without blocking the request or changing its decision.
 */
class HistoryProviderFailureTest {

    private static final Duration WINDOW = Duration.ofHours(1);
    private static final RequestContext ALICE = RiskTestContexts.authenticated("alice");

    private static List<ContextualInputProvider<?>> providers(ClientActivityHistory history) {
        return List.of(new ClientHistoryProvider(history, WINDOW), new ThreatHistoryProvider(history, WINDOW));
    }

    /** A real R2DBC PostgreSQL client pointed at a port where nothing listens. */
    private static ClientActivityHistory unreachablePostgres() {
        return new PostgresClientActivityHistory(DatabaseClient.create(
                ConnectionFactories.get("r2dbc:postgresql://apishield:unused@127.0.0.1:1/apishield_db")));
    }

    private static ContextualInputs collect(ClientActivityHistory history, Duration timeout) {
        return new ContextualInputCollector(providers(history), timeout).collect(ALICE).block(Duration.ofSeconds(10));
    }

    private static void assertBothMissingAndDegraded(ContextualInputs inputs) {
        assertThat(inputs.get(ClientHistory.class)).isEmpty();
        assertThat(inputs.get(ThreatHistory.class)).isEmpty();
        assertThat(inputs.failed(ClientHistory.class)).isTrue();
        assertThat(inputs.failed(ThreatHistory.class)).isTrue();
        assertThat(inputs.degraded()).isTrue();
    }

    @Test
    void postgresUnavailableMakesHistoryMissingAndDegraded() {
        assertBothMissingAndDegraded(collect(unreachablePostgres(), Duration.ofSeconds(5)));
    }

    @Test
    void slowPostgresTimesOutAndMakesHistoryMissingAndDegraded() {
        ClientActivityHistory hanging = new RecordingActivityHistory() {
            @Override
            public Mono<ActivityCounts> activity(ClientKey clientKey, Instant since, Instant until) {
                return Mono.never();
            }

            @Override
            public Mono<Long> threatEventCount(ClientKey clientKey, Instant since, Instant until, double min) {
                return Mono.never();
            }
        };

        StepVerifier.withVirtualTime(() -> new ContextualInputCollector(providers(hanging), Duration.ofMillis(100)).collect(ALICE))
                .thenAwait(Duration.ofMillis(100))
                .assertNext(HistoryProviderFailureTest::assertBothMissingAndDegraded)
                .verifyComplete();
    }

    @Test
    void malformedResultMakesHistoryMissingAndDegraded() {
        ClientActivityHistory malformed = new RecordingActivityHistory() {
            @Override
            public Mono<ActivityCounts> activity(ClientKey clientKey, Instant since, Instant until) {
                return Mono.fromCallable(() -> new ActivityCounts(3, 4)); // blocked > requests
            }

            @Override
            public Mono<Long> threatEventCount(ClientKey clientKey, Instant since, Instant until, double min) {
                return Mono.just(-1L); // rejected by ThreatHistory
            }
        };

        assertBothMissingAndDegraded(collect(malformed, Duration.ofSeconds(5)));
    }

    @Test
    void postgresOutageNeitherBlocksNorChangesAnyDecision() {
        List<Recorded> recorded = new ArrayList<>();
        SecurityEventRecorder recorder = (request, riskScore, decision) -> recorded.add(new Recorded(riskScore, decision));
        ContextualRiskScoreEngine engine = new ContextualRiskScoreEngine(List.of(new RouteSensitivityRiskFactor(),
                new IdentityRiskFactor(), new ClientHistoryRiskFactor(), new ThreatHistoryRiskFactor()), false);
        ContextualInputCollector collector = new ContextualInputCollector(providers(unreachablePostgres()), Duration.ofSeconds(5));

        for (double severity : new double[]{0.1, 0.3, 0.9}) {
            ThreatDetector detector = ctx -> Mono.just(new ThreatSignal("detector", true, severity, "matched"));
            SecurityPipeline withHistory = new SecurityPipeline(List.of(detector), engine, new DefaultDecisionEngine(), recorder, collector);
            SecurityPipeline withoutHistory = new SecurityPipeline(List.of(detector), engine, new DefaultDecisionEngine(), (r, s, d) -> { });

            Decision expected = withoutHistory.evaluate(ALICE).block(Duration.ofSeconds(10));
            StepVerifier.create(withHistory.evaluate(ALICE))
                    .assertNext(decision -> assertThat(decision).isEqualTo(expected))
                    .verifyComplete();
        }

        assertThat(recorded).extracting(r -> r.decision().outcome())
                .containsExactly(Decision.Outcome.ALLOW, Decision.Outcome.MONITOR, Decision.Outcome.BLOCK);
        assertThat(recorded).allSatisfy(r -> assertThat(r.riskScore().degraded()).isTrue());
    }

    private record Recorded(RiskScore riskScore, Decision decision) {
    }
}
