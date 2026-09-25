package com.apishield.risk.context.history;

import com.apishield.risk.context.ClientKey;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Aggregate questions about a client's recent activity, answered from persisted security events.
 * Implementations must aggregate in the data store (counts only) - never load event histories.
 * <p>
 * The window is always half-open, {@code [since, until)}. Events are attributed to clients exactly as
 * {@link ClientKey#of} attributes requests: an event with a user belongs to that user; an event without
 * one belongs to its client IP.
 */
public interface ClientActivityHistory {

    /** Evaluated requests, and how many of them were blocked, for one client within the window. */
    Mono<ActivityCounts> activity(ClientKey clientKey, Instant since, Instant until);

    /** Evaluated requests whose detector-only threat score reached {@code minThreatScore}, within the window. */
    Mono<Long> threatEventCount(ClientKey clientKey, Instant since, Instant until, double minThreatScore);

    record ActivityCounts(long requests, long blocked) {

        public ActivityCounts {
            if (requests < 0 || blocked < 0 || blocked > requests) {
                throw new IllegalArgumentException(
                        "require 0 <= blocked <= requests, was " + blocked + "/" + requests);
            }
        }
    }
}
