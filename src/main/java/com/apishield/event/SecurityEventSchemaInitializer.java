package com.apishield.event;

import io.r2dbc.spi.ConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.r2dbc.connection.init.ResourceDatabasePopulator;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Applies {@code db/schema.sql} at startup. The script is idempotent ({@code IF NOT EXISTS}), so this is
 * safe on every start.
 * <p>
 * Deliberately not Spring Boot's {@code spring.sql.init.mode=always}: that fails application startup
 * when PostgreSQL is unreachable, which would turn a database outage into a gateway outage. Security
 * event persistence is secondary to the gateway's job, so here a failure is logged and startup
 * continues; events simply fail to persist (and are logged) until the database and table are available.
 * <p>
 * Runs on the main thread during startup, never on a request-handling event loop, so waiting (with a
 * bound) is safe here.
 */
@Component
public class SecurityEventSchemaInitializer implements ApplicationRunner {

    static final Duration TIMEOUT = Duration.ofSeconds(10);

    private static final Logger log = LoggerFactory.getLogger(SecurityEventSchemaInitializer.class);

    private final ConnectionFactory connectionFactory;

    public SecurityEventSchemaInitializer(ConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            new ResourceDatabasePopulator(new ClassPathResource("db/schema.sql"))
                    .populate(connectionFactory)
                    .block(TIMEOUT);
            log.info("Security event schema is up to date");
        } catch (RuntimeException ex) {
            log.warn("Could not apply security event schema - security events will not be persisted "
                    + "until the database is reachable: {}", ex.toString());
        }
    }
}
