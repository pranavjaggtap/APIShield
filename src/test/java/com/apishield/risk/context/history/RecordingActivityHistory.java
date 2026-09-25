package com.apishield.risk.context.history;

import com.apishield.risk.context.ClientKey;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Test double for {@link ClientActivityHistory}: answers from per-client canned counts (zero for any
 * client not configured, like an empty table) and records the arguments of the last query.
 */
class RecordingActivityHistory implements ClientActivityHistory {

    private final Map<ClientKey, ActivityCounts> activity = new HashMap<>();
    private final Map<ClientKey, Long> threats = new HashMap<>();

    ClientKey lastClientKey;
    Instant lastSince;
    Instant lastUntil;
    Double lastMinThreatScore;

    RecordingActivityHistory withActivity(ClientKey key, long requests, long blocked) {
        activity.put(key, new ActivityCounts(requests, blocked));
        return this;
    }

    RecordingActivityHistory withThreats(ClientKey key, long count) {
        threats.put(key, count);
        return this;
    }

    @Override
    public Mono<ActivityCounts> activity(ClientKey clientKey, Instant since, Instant until) {
        record(clientKey, since, until);
        return Mono.just(activity.getOrDefault(clientKey, new ActivityCounts(0, 0)));
    }

    @Override
    public Mono<Long> threatEventCount(ClientKey clientKey, Instant since, Instant until, double minThreatScore) {
        record(clientKey, since, until);
        lastMinThreatScore = minThreatScore;
        return Mono.just(threats.getOrDefault(clientKey, 0L));
    }

    private void record(ClientKey clientKey, Instant since, Instant until) {
        lastClientKey = clientKey;
        lastSince = since;
        lastUntil = until;
    }
}
