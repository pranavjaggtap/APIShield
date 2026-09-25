package com.apishield.event;

import com.apishield.model.Decision;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.history.ClientActivityHistory;
import io.r2dbc.spi.Readable;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Objects;

/**
 * {@link ClientActivityHistory} answered by aggregate SQL over the {@code security_events} table - one
 * row of counts per query, never event rows. Only sanitized, already-persisted columns are read
 * ({@code user_id}, {@code client_ip}, {@code occurred_at}, {@code decision}, {@code threat_score}); no
 * credentials exist in that table to query.
 * <p>
 * Client attribution mirrors {@link ClientKey#of}: USER keys match {@code user_id}; IP keys match only
 * events without a user ({@code user_id IS NULL}) from that IP, so an authenticated user's traffic is
 * never counted against the IP they happened to share. Values are always bound, never concatenated.
 * <p>
 * Indexing: USER queries use the existing partial index {@code (user_id, occurred_at DESC)}. IP queries
 * have no dedicated index and would scan by time range; they are unreachable today because the gateway
 * rejects unauthenticated requests before the security pipeline. Add an index on
 * {@code (client_ip, occurred_at) WHERE user_id IS NULL} before enabling unauthenticated routes.
 */
@Component
public class PostgresClientActivityHistory implements ClientActivityHistory {

    static final String USER_PREDICATE = "user_id = :client";
    static final String IP_PREDICATE = "user_id IS NULL AND client_ip = :client";

    private static final String WINDOW_PREDICATE = "occurred_at >= :since AND occurred_at < :until";

    private static final String ACTIVITY_SQL = """
            SELECT count(*) AS requests,
                   count(*) FILTER (WHERE decision = :blocked) AS blocked
            FROM security_events
            WHERE %s AND %s""";

    private static final String THREAT_SQL = """
            SELECT count(*) AS threats
            FROM security_events
            WHERE %s AND %s AND threat_score >= :minThreatScore""";

    private final DatabaseClient databaseClient;

    public PostgresClientActivityHistory(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    @Override
    public Mono<ActivityCounts> activity(ClientKey clientKey, Instant since, Instant until) {
        return databaseClient.sql(ACTIVITY_SQL.formatted(clientPredicate(clientKey), WINDOW_PREDICATE))
                .bind("client", clientKey.value())
                .bind("since", since)
                .bind("until", until)
                .bind("blocked", Decision.Outcome.BLOCK.name())
                .map((row, metadata) -> toActivityCounts(row))
                .one();
    }

    @Override
    public Mono<Long> threatEventCount(ClientKey clientKey, Instant since, Instant until, double minThreatScore) {
        return databaseClient.sql(THREAT_SQL.formatted(clientPredicate(clientKey), WINDOW_PREDICATE))
                .bind("client", clientKey.value())
                .bind("since", since)
                .bind("until", until)
                .bind("minThreatScore", minThreatScore)
                .map((row, metadata) -> requireCount(row, "threats"))
                .one();
    }

    static String clientPredicate(ClientKey clientKey) {
        return switch (clientKey.kind()) {
            case USER -> USER_PREDICATE;
            case IP -> IP_PREDICATE;
        };
    }

    /** Throws on null/negative/inconsistent counts, so a malformed result surfaces as a provider error. */
    static ActivityCounts toActivityCounts(Readable row) {
        return new ActivityCounts(requireCount(row, "requests"), requireCount(row, "blocked"));
    }

    static long requireCount(Readable row, String column) {
        Long value = row.get(column, Long.class);
        Objects.requireNonNull(value, () -> "null count in column '" + column + "'");
        if (value < 0) {
            throw new IllegalStateException("negative count in column '" + column + "': " + value);
        }
        return value;
    }
}
