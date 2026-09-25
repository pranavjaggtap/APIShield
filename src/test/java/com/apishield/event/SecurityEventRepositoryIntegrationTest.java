package com.apishield.event;

import com.apishield.context.RequestContext;
import com.apishield.context.RouteInfo;
import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.r2dbc.core.DatabaseClient;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Round-trips security events through a live PostgreSQL. Skipped by default so {@code ./mvnw test}
 * never requires a database; run explicitly with {@code DB_INTEGRATION_TEST=true ./mvnw test} against a
 * reachable PostgreSQL. The schema is applied by SecurityEventSchemaInitializer at context startup.
 * <p>
 * Safe against a shared development database: every row this test creates has a request id with a
 * per-run prefix, assertions only look at those rows, and only those rows are deleted afterwards. Rows
 * are dated in the year 2100 so they sort ahead of any real events.
 */
@SpringBootTest
@EnabledIfEnvironmentVariable(named = "DB_INTEGRATION_TEST", matches = "true")
class SecurityEventRepositoryIntegrationTest {

    private static final Instant BASE_TIME = Instant.parse("2100-01-01T00:00:00.123456Z");

    private final String prefix = "it-" + UUID.randomUUID() + "-";

    @Autowired
    private SecurityEventRepository repository;

    @Autowired
    private AsyncSecurityEventRecorder recorder;

    @Autowired
    private DatabaseClient databaseClient;

    @AfterEach
    void deleteOwnRows() {
        databaseClient.sql("DELETE FROM security_events WHERE request_id LIKE :prefix")
                .bind("prefix", prefix + "%")
                .fetch().rowsUpdated()
                .block(Duration.ofSeconds(10));
    }

    private SecurityEvent event(String requestSuffix, Instant occurredAt, String decision, String userId) {
        return new SecurityEvent(null, prefix + requestSuffix, occurredAt, "GET", "/api/users/1", "10.0.0.5",
                userId, "user-service", decision, decision + " reason", 0.9, 0.85,
                List.of("sql-injection", "xss"), List.of(true, false), List.of(0.9, 0.0),
                List.of("matched: tautology", "no XSS patterns matched"));
    }

    private List<SecurityEvent> own(List<SecurityEvent> events) {
        return events.stream().filter(e -> e.requestId().startsWith(prefix)).toList();
    }

    @Test
    void saveGeneratesIdAndFindByIdRoundTripsEveryField() {
        SecurityEvent saved = repository.save(event("a", BASE_TIME, "BLOCK", "user-42")).block();

        assertThat(saved).isNotNull();
        assertThat(saved.id()).isNotNull();

        SecurityEvent loaded = repository.findById(saved.id()).block();
        assertThat(loaded).isEqualTo(saved);
        assertThat(loaded.occurredAt()).isEqualTo(BASE_TIME);
        assertThat(loaded.riskScore()).isEqualTo(0.9);
        assertThat(loaded.threatScore()).isEqualTo(0.85);
        assertThat(loaded.threatSignals()).containsExactly(
                new ThreatSignal("sql-injection", true, 0.9, "matched: tautology"),
                new ThreatSignal("xss", false, 0.0, "no XSS patterns matched"));
    }

    @Test
    void nullUserIdAndEmptySignalsRoundTrip() {
        SecurityEvent saved = repository.save(new SecurityEvent(null, prefix + "anon", BASE_TIME, "GET", "/", "10.0.0.5",
                null, null, "ALLOW", "ok", 0.0, 0.0, List.of(), List.of(), List.of(), List.of())).block();

        SecurityEvent loaded = repository.findById(saved.id()).block();
        assertThat(loaded.userId()).isNull();
        assertThat(loaded.routeId()).isNull();
        assertThat(loaded.threatSignals()).isEmpty();
    }

    @Test
    void listIsNewestFirstWithIdTieBreakAndStablePaging() {
        SecurityEvent oldest = repository.save(event("1", BASE_TIME, "ALLOW", null)).block();
        SecurityEvent tiedA = repository.save(event("2", BASE_TIME.plusSeconds(10), "BLOCK", null)).block();
        SecurityEvent tiedB = repository.save(event("3", BASE_TIME.plusSeconds(10), "ALLOW", null)).block();
        SecurityEvent newest = repository.save(event("4", BASE_TIME.plusSeconds(20), "BLOCK", null)).block();

        List<SecurityEvent> all = own(repository.findAllByOrderByOccurredAtDescIdDesc(PageRequest.of(0, 100))
                .collectList().block());

        // PostgreSQL orders UUIDs as unsigned bytes; Java's UUID.compareTo compares signed longs and
        // disagrees whenever the leading hex digit is >= 8. Canonical lowercase strings order like PostgreSQL.
        SecurityEvent tiedHigherId = tiedA.id().toString().compareTo(tiedB.id().toString()) > 0 ? tiedA : tiedB;
        SecurityEvent tiedLowerId = tiedHigherId == tiedA ? tiedB : tiedA;
        assertThat(all).containsExactly(newest, tiedHigherId, tiedLowerId, oldest);

        List<SecurityEvent> firstPage = repository.findAllByOrderByOccurredAtDescIdDesc(PageRequest.of(0, 2))
                .collectList().block();
        List<SecurityEvent> secondPage = repository.findAllByOrderByOccurredAtDescIdDesc(PageRequest.of(1, 2))
                .collectList().block();
        assertThat(firstPage).containsExactly(newest, tiedHigherId);
        assertThat(secondPage).containsExactly(tiedLowerId, oldest);
    }

    @Test
    void decisionFilterReturnsOnlyMatchingEventsNewestFirst() {
        Long blockedBefore = repository.countByDecision("BLOCK").block();
        repository.save(event("allow", BASE_TIME.plusSeconds(30), "ALLOW", null)).block();
        SecurityEvent olderBlock = repository.save(event("block-1", BASE_TIME, "BLOCK", null)).block();
        SecurityEvent newerBlock = repository.save(event("block-2", BASE_TIME.plusSeconds(5), "BLOCK", null)).block();

        List<SecurityEvent> blocked = own(repository.findByDecisionOrderByOccurredAtDescIdDesc("BLOCK",
                PageRequest.of(0, 100)).collectList().block());

        assertThat(blocked).containsExactly(newerBlock, olderBlock);
        assertThat(repository.countByDecision("BLOCK").block()).isEqualTo(blockedBefore + 2);
    }

    @Test
    void recorderPersistsEventFromARealDecision() throws InterruptedException {
        RequestContext request = new RequestContext(prefix + "recorded", "POST", "/api/users/1", java.util.Map.of(),
                java.util.Map.of(), "10.0.0.9", BASE_TIME, Optional.of(new RouteInfo("user-service",
                URI.create("http://localhost:8081"))), Optional.of("user-42"));
        RiskScore riskScore = RiskScore.fromSignalsOnly(0.9,
                List.of(new ThreatSignal("replay-attack", true, 0.9, "nonce already used")));
        Decision decision = new Decision(Decision.Outcome.BLOCK, "risk score 0.90 met or exceeded block threshold 0.50");

        recorder.record(request, riskScore, decision);

        SecurityEvent persisted = null;
        long deadline = System.currentTimeMillis() + 5000;
        while (persisted == null && System.currentTimeMillis() < deadline) {
            persisted = own(repository.findAllByOrderByOccurredAtDescIdDesc(PageRequest.of(0, 100))
                    .collectList().block()).stream()
                    .filter(e -> e.requestId().equals(prefix + "recorded"))
                    .findFirst().orElse(null);
            if (persisted == null) {
                Thread.sleep(50);
            }
        }

        assertThat(persisted).isNotNull();
        assertThat(persisted.userId()).isEqualTo("user-42");
        assertThat(persisted.decision()).isEqualTo("BLOCK");
        assertThat(persisted.riskScore()).isEqualTo(0.9);
        assertThat(persisted.threatScore()).isEqualTo(0.9);
        assertThat(persisted.signalDetectors()).containsExactly("replay-attack");
    }
}
