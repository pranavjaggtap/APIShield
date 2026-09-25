package com.apishield.event;

import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.history.ClientActivityHistory.ActivityCounts;
import io.r2dbc.spi.Readable;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Query shape and result mapping without a database. Behavior against real PostgreSQL is covered by
 * PostgresClientActivityHistoryIntegrationTest (DB_INTEGRATION_TEST=true).
 */
class PostgresClientActivityHistoryTest {

    private static Readable row(Long requests, Long blocked) {
        Map<String, Long> values = new HashMap<>();
        values.put("requests", requests);
        values.put("blocked", blocked);
        Readable row = mock(Readable.class);
        when(row.get(anyString(), eq(Long.class))).thenAnswer(invocation -> values.get(invocation.<String>getArgument(0)));
        return row;
    }

    @Test
    void userKeyMatchesUserIdOnly() {
        assertThat(PostgresClientActivityHistory.clientPredicate(new ClientKey(ClientKey.Kind.USER, "alice")))
                .isEqualTo("user_id = :client");
    }

    @Test
    void ipKeyMatchesOnlyUnauthenticatedEventsFromThatIp() {
        assertThat(PostgresClientActivityHistory.clientPredicate(new ClientKey(ClientKey.Kind.IP, "10.0.0.5")))
                .isEqualTo("user_id IS NULL AND client_ip = :client");
    }

    @Test
    void predicatesBindValuesAndNeverEmbedThem() {
        assertThat(PostgresClientActivityHistory.clientPredicate(new ClientKey(ClientKey.Kind.USER, "x' OR '1'='1")))
                .doesNotContain("x'").contains(":client");
    }

    @Test
    void mapsAggregateRow() {
        assertThat(PostgresClientActivityHistory.toActivityCounts(row(20L, 5L))).isEqualTo(new ActivityCounts(20, 5));
        assertThat(PostgresClientActivityHistory.toActivityCounts(row(0L, 0L))).isEqualTo(new ActivityCounts(0, 0));
    }

    @Test
    void nullCountIsMalformed() {
        assertThatThrownBy(() -> PostgresClientActivityHistory.toActivityCounts(row(null, 0L)))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("requests");
        assertThatThrownBy(() -> PostgresClientActivityHistory.toActivityCounts(row(3L, null)))
                .isInstanceOf(NullPointerException.class).hasMessageContaining("blocked");
    }

    @Test
    void negativeCountIsMalformed() {
        assertThatThrownBy(() -> PostgresClientActivityHistory.toActivityCounts(row(-1L, 0L)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void moreBlockedThanRequestsIsMalformed() {
        assertThatThrownBy(() -> PostgresClientActivityHistory.toActivityCounts(row(3L, 4L)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
