package com.apishield;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;

/**
 * Verifies a live round-trip to PostgreSQL. Skipped by default so {@code ./mvnw test}
 * never requires a running database; run explicitly with
 * {@code DB_INTEGRATION_TEST=true ./mvnw test} against a reachable PostgreSQL instance.
 */
@SpringBootTest
@EnabledIfEnvironmentVariable(named = "DB_INTEGRATION_TEST", matches = "true")
class PostgresConnectivityTest {

    @Autowired
    private DatabaseClient databaseClient;

    @Test
    void canConnectToPostgres() {
        StepVerifier.create(databaseClient.sql("SELECT 1").fetch().first())
                .expectNextCount(1)
                .verifyComplete();
    }

}
