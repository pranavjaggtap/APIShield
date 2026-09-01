package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Redis-backed frequency/abuse detector. Counts requests per client identity within a fixed
 * window and flags a threat once the count reaches a threshold. This is a threat-detection
 * signal within the existing SQLi/XSS/Replay pipeline, not a rate-limiter subsystem: a flagged
 * request gets the same generic 403 as any other detected threat, not a 429/Retry-After
 * response, and there is no per-client-configurable quota or burst-tolerance algorithm here.
 * <p>
 * Client identity is the actual TCP-level remote address ({@link SecurityAnalysisContext#clientIp()}),
 * not {@code X-Forwarded-For} - deliberately, since this deployment has no trusted upstream
 * proxy to validate that header, and trusting it would let an attacker evade counting simply
 * by rotating a spoofed value per request. Identity resolution is isolated in one small method
 * so it can be replaced with an authenticated client ID later without touching the rest of
 * this detector.
 * <p>
 * Redis's {@code INCR} guarantees each caller receives a unique, strictly increasing integer,
 * so exactly one caller per fresh window will ever observe a count of 1; only that caller sets
 * the window's TTL. This makes the two-call increment-then-expire sequence race-free for this
 * purpose without needing a Lua script or conditional (NX) expiry.
 * <p>
 * Redis errors are not caught here; they propagate as-is so {@link com.apishield.security.SecurityPipeline}'s
 * existing fail-closed handling converts any failure into a blocking signal. Because every
 * request needs to be counted (unlike replay detection, which only contacts Redis when a nonce
 * is present), this detector contacts Redis unconditionally - a Redis outage will fail-closed
 * every request, not a subset.
 */
@Component
public class FrequencyAbuseDetector implements ThreatDetector {

    private static final String DETECTOR_NAME = "frequency-abuse";

    /**
     * Fixed window and threshold for this milestone: 60 seconds, 20 requests. Named constants,
     * not externalized configuration yet - see the reviewed plan for the justification.
     */
    public static final Duration WINDOW = Duration.ofSeconds(60);
    public static final long THRESHOLD = 20;

    private static final double ABUSE_SEVERITY = 0.9;

    private final ReactiveStringRedisTemplate redisTemplate;
    private final Duration window;
    private final long threshold;

    @Autowired
    public FrequencyAbuseDetector(ReactiveStringRedisTemplate redisTemplate) {
        this(redisTemplate, WINDOW, THRESHOLD);
    }

    /**
     * Allows tests to inject a short window and low threshold instead of waiting out the real
     * 60-second/20-request defaults.
     */
    public FrequencyAbuseDetector(ReactiveStringRedisTemplate redisTemplate, Duration window, long threshold) {
        this.redisTemplate = redisTemplate;
        this.window = window;
        this.threshold = threshold;
    }

    @Override
    public Mono<ThreatSignal> detect(SecurityAnalysisContext context) {
        String clientId = resolveClientIdentity(context);
        String key = "apishield:frequency:" + clientId;

        return redisTemplate.opsForValue().increment(key)
                .flatMap(count -> {
                    Mono<ThreatSignal> signal = Mono.just(count >= threshold
                            ? abuseSignal(clientId, count)
                            : cleanSignal(clientId, count));
                    return count == 1
                            ? redisTemplate.expire(key, window).then(signal)
                            : signal;
                });
    }

    /**
     * The actual TCP-level remote address, never {@code X-Forwarded-For}. Isolated here so the
     * identity source can be swapped for an authenticated client ID later without redesigning
     * the rest of this detector. "unknown" (the existing fallback already used elsewhere when
     * the remote address is unavailable) is treated as a normal, if coarse, grouping key - not
     * exempted from counting, since that would be a trivial detection bypass.
     */
    private String resolveClientIdentity(SecurityAnalysisContext context) {
        String clientIp = context.clientIp();
        return (clientIp == null || clientIp.isBlank()) ? "unknown" : clientIp;
    }

    private ThreatSignal cleanSignal(String clientId, long count) {
        String description = "client '" + clientId + "' made " + count + " request(s) within "
                + window.getSeconds() + "s window (threshold " + threshold + ")";
        return new ThreatSignal(DETECTOR_NAME, false, 0.0, description);
    }

    private ThreatSignal abuseSignal(String clientId, long count) {
        String description = "client '" + clientId + "' made " + count + " requests within "
                + window.getSeconds() + "s window (threshold " + threshold + ")";
        return new ThreatSignal(DETECTOR_NAME, true, ABUSE_SEVERITY, description);
    }
}
