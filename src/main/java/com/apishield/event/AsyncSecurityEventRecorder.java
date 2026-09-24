package com.apishield.event;

import com.apishield.context.RequestContext;
import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Persists security events in the background: {@link #record} starts a non-blocking save and returns
 * immediately, so request latency and the security decision never depend on PostgreSQL.
 * <p>
 * The background work is bounded so a slow or unavailable database cannot exhaust memory or
 * connections:
 * <ul>
 *   <li>each save is abandoned after {@link #SAVE_TIMEOUT};</li>
 *   <li>at most {@link #MAX_IN_FLIGHT} saves are pending at once - further events are dropped (and
 *       logged) rather than queued without limit.</li>
 * </ul>
 * Persistence is therefore best-effort: an event can be lost during a database outage, an overload or
 * a shutdown. Failures are logged without event contents, and never propagate to the caller.
 */
@Component
public class AsyncSecurityEventRecorder implements SecurityEventRecorder {

    public static final Duration SAVE_TIMEOUT = Duration.ofSeconds(5);
    public static final int MAX_IN_FLIGHT = 256;

    private static final Logger log = LoggerFactory.getLogger(AsyncSecurityEventRecorder.class);

    private final SecurityEventRepository repository;
    private final Duration saveTimeout;
    private final int maxInFlight;
    private final AtomicInteger inFlight = new AtomicInteger();

    @Autowired
    public AsyncSecurityEventRecorder(SecurityEventRepository repository) {
        this(repository, SAVE_TIMEOUT, MAX_IN_FLIGHT);
    }

    /**
     * Allows tests to use a short timeout and a small in-flight limit.
     */
    public AsyncSecurityEventRecorder(SecurityEventRepository repository, Duration saveTimeout, int maxInFlight) {
        this.repository = repository;
        this.saveTimeout = saveTimeout;
        this.maxInFlight = maxInFlight;
    }

    @Override
    public void record(RequestContext request, RiskScore riskScore, Decision decision) {
        SecurityEvent event;
        try {
            event = SecurityEvent.create(request, riskScore, decision);
        } catch (RuntimeException ex) {
            log.error("Could not build security event for request {}: {}", request.requestId(), ex.toString());
            return;
        }

        if (inFlight.incrementAndGet() > maxInFlight) {
            inFlight.decrementAndGet();
            log.warn("Dropped security event for request {} ({}): {} saves already pending",
                    event.requestId(), event.decision(), maxInFlight);
            return;
        }

        Mono.defer(() -> repository.save(event))
                .timeout(saveTimeout)
                .doFinally(signal -> inFlight.decrementAndGet())
                .subscribe(
                        saved -> { },
                        error -> log.warn("Failed to persist security event for request {} ({}): {}",
                                event.requestId(), event.decision(), error.toString()));
    }

    /** Number of saves currently pending. */
    int inFlight() {
        return inFlight.get();
    }
}
