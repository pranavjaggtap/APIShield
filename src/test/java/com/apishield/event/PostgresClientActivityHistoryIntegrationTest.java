package com.apishield.event;

import com.apishield.context.RequestContext;
import com.apishield.context.RouteInfo;
import com.apishield.model.Decision;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputCollector;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.history.ClientActivityHistory.ActivityCounts;
import com.apishield.risk.context.history.ClientHistoryProvider;
import com.apishield.risk.context.history.ThreatHistoryProvider;
import com.apishield.risk.context.inputs.ClientHistory;
import com.apishield.risk.context.inputs.ThreatHistory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The history SQL against a live PostgreSQL. Skipped by default; run with
 * {@code DB_INTEGRATION_TEST=true ./mvnw test} against a reachable PostgreSQL (schema applied at startup).
 * <p>
 * Safe against a shared development database: every row uses per-run user ids / client IPs and a per-run
 * request-id prefix, is dated in the year 2100, and only those rows are deleted afterwards.
 */
@SpringBootTest
@EnabledIfEnvironmentVariable(named = "DB_INTEGRATION_TEST", matches = "true")
class PostgresClientActivityHistoryIntegrationTest {

    private static final Instant UNTIL = Instant.parse("2100-01-01T12:00:00Z");
    private static final Duration WINDOW = Duration.ofHours(1);
    private static final Instant SINCE = UNTIL.minus(WINDOW);
    private static final Duration MICRO = Duration.ofNanos(1_000);

    private final String run = UUID.randomUUID().toString();
    private final String prefix = "it-hist-" + run + "-";
    private final String alice = "alice-" + run;
    private final String bob = "bob-" + run;
    private final String sharedIp = "ip-" + run;

    @Autowired
    private SecurityEventRepository repository;

    @Autowired
    private PostgresClientActivityHistory history;

    @Autowired
    private DatabaseClient databaseClient;

    private int sequence;

    @AfterEach
    void deleteOwnRows() {
        databaseClient.sql("DELETE FROM security_events WHERE request_id LIKE :prefix")
                .bind("prefix", prefix + "%")
                .fetch().rowsUpdated()
                .block(Duration.ofSeconds(10));
    }

    private void event(String userId, String clientIp, Instant at, Decision.Outcome decision, double threatScore) {
        repository.save(new SecurityEvent(null, prefix + (sequence++), at, "GET", "/api/users/1", clientIp, userId,
                "user-service", decision.name(), "test", threatScore, threatScore,
                List.of(), List.of(), List.of(), List.of())).block(Duration.ofSeconds(10));
    }

    private ActivityCounts activity(ClientKey key) {
        return history.activity(key, SINCE, UNTIL).block(Duration.ofSeconds(10));
    }

    private long threats(ClientKey key) {
        return history.threatEventCount(key, SINCE, UNTIL, ThreatHistoryProvider.MIN_THREAT_SCORE).block(Duration.ofSeconds(10));
    }

    private ClientKey user(String id) {
        return new ClientKey(ClientKey.Kind.USER, id);
    }

    @Test
    void noHistoryIsZeroNotMissing() {
        assertThat(activity(user(alice))).isEqualTo(new ActivityCounts(0, 0));
        assertThat(threats(user(alice))).isZero();
    }

    @Test
    void windowIsHalfOpenAndAnchoredToTheGivenInstants() {
        event(alice, sharedIp, SINCE, Decision.Outcome.ALLOW, 0.0);                  // included (lower bound)
        event(alice, sharedIp, UNTIL.minus(MICRO), Decision.Outcome.ALLOW, 0.0);     // included
        event(alice, sharedIp, UNTIL, Decision.Outcome.BLOCK, 0.9);                  // excluded (upper bound)
        event(alice, sharedIp, SINCE.minus(MICRO), Decision.Outcome.BLOCK, 0.9);     // excluded (too old)

        assertThat(activity(user(alice))).isEqualTo(new ActivityCounts(2, 0));
        assertThat(threats(user(alice))).isZero();
    }

    @Test
    void onlyBlockDecisionsCountAsBlocked() {
        Instant at = SINCE.plusSeconds(60);
        for (Decision.Outcome outcome : Decision.Outcome.values()) {
            event(alice, sharedIp, at, outcome, 0.1);
        }
        event(alice, sharedIp, at, Decision.Outcome.BLOCK, 0.1);

        assertThat(activity(user(alice))).isEqualTo(new ActivityCounts(6, 2));
    }

    @Test
    void otherClientsAreExcluded() {
        Instant at = SINCE.plusSeconds(60);
        event(alice, sharedIp, at, Decision.Outcome.BLOCK, 0.9);
        event(bob, sharedIp, at, Decision.Outcome.BLOCK, 0.9);
        event(bob, sharedIp, at, Decision.Outcome.ALLOW, 0.0);

        assertThat(activity(user(alice))).isEqualTo(new ActivityCounts(1, 1));
        assertThat(activity(user(bob))).isEqualTo(new ActivityCounts(2, 1));
        assertThat(threats(user(alice))).isEqualTo(1);
    }

    @Test
    void ipKeyCountsOnlyUnauthenticatedEventsFromThatIp() {
        Instant at = SINCE.plusSeconds(60);
        event(alice, sharedIp, at, Decision.Outcome.BLOCK, 0.9);  // authenticated - belongs to alice, not the IP
        event(null, sharedIp, at, Decision.Outcome.ALLOW, 0.0);
        event(null, sharedIp, at, Decision.Outcome.BLOCK, 0.95);
        event(null, "other-" + sharedIp, at, Decision.Outcome.BLOCK, 0.95);

        ClientKey ip = new ClientKey(ClientKey.Kind.IP, sharedIp);
        assertThat(activity(ip)).isEqualTo(new ActivityCounts(2, 1));
        assertThat(threats(ip)).isEqualTo(1);
    }

    @Test
    void threatEventsUseTheDetectorOnlyScoreAtTheBlockThresholdRegardlessOfDecision() {
        Instant at = SINCE.plusSeconds(60);
        event(alice, sharedIp, at, Decision.Outcome.BLOCK, 0.80);                   // counted: at threshold
        event(alice, sharedIp, at, Decision.Outcome.CHALLENGE, 1.0);                 // counted: decision irrelevant
        event(alice, sharedIp, at, Decision.Outcome.BLOCK, Math.nextDown(0.80));    // not counted: context-driven block
        event(alice, sharedIp, at, Decision.Outcome.ALLOW, 0.2);                     // not counted: weak signal

        assertThat(threats(user(alice))).isEqualTo(2);
        assertThat(activity(user(alice))).isEqualTo(new ActivityCounts(4, 2));
    }

    @Test
    void providersSupplyRealHistoryThroughTheCollector() {
        Instant at = SINCE.plusSeconds(60);
        for (int i = 0; i < 12; i++) {
            event(alice, sharedIp, at, i < 3 ? Decision.Outcome.BLOCK : Decision.Outcome.ALLOW, i < 3 ? 0.9 : 0.0);
        }
        RequestContext request = new RequestContext(prefix + "req", "GET", "/api/users/1", Map.of(), Map.of(), sharedIp,
                UNTIL, Optional.of(new RouteInfo("user-service", URI.create("http://localhost:8081"))), Optional.of(alice));
        ContextualInputCollector collector = new ContextualInputCollector(
                List.of(new ClientHistoryProvider(history, WINDOW), new ThreatHistoryProvider(history, WINDOW)),
                Duration.ofSeconds(5));

        ContextualInputs inputs = collector.collect(request).block(Duration.ofSeconds(10));

        assertThat(inputs.degraded()).isFalse();
        assertThat(inputs.get(ClientHistory.class)).contains(new ClientHistory(user(alice), 12, 3, WINDOW));
        assertThat(inputs.get(ThreatHistory.class)).contains(new ThreatHistory(user(alice), 3, WINDOW));
    }
}
