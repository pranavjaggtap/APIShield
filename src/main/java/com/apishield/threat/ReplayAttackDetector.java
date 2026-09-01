package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Redis-backed replay attack detector. A client that wants replay protection presents a
 * single-use token in the {@code X-APIShield-Nonce} header; the detector atomically claims
 * that nonce (scoped to HTTP method + path) in Redis with a TTL, and flags a request as a
 * replay if the same nonce was already claimed.
 * <p>
 * Demo policy, deliberately documented rather than hidden: requests without a usable nonce
 * are allowed and never contact Redis - this detector protects only the traffic that opts
 * in by presenting a nonce. A future authentication/API-key layer is the natural point to
 * require a nonce for protected traffic; that is not implemented here.
 * <p>
 * This is not complete replay protection on its own: the nonce is not bound to an
 * authenticated client identity or a signature, so it only prevents literal reuse of a
 * specific captured token, scoped to one method+path, within the TTL window. Production-grade
 * replay protection should additionally bind the nonce to client identity and typically a
 * timestamp/signature (e.g. HMAC) - both explicitly out of scope for this milestone.
 * <p>
 * Redis errors are deliberately not caught here: they propagate as-is, so
 * {@link com.apishield.security.SecurityPipeline}'s existing fail-closed handling converts
 * any Redis failure into a blocking signal rather than silently allowing a nonce-bearing
 * request through unexamined.
 */
@Component
public class ReplayAttackDetector implements ThreatDetector {

    private static final String DETECTOR_NAME = "replay-attack";
    private static final String NONCE_HEADER = "X-APIShield-Nonce";
    private static final int MAX_NONCE_LENGTH = 256;
    private static final Pattern SAFE_NONCE = Pattern.compile("^[A-Za-z0-9._-]+$");
    private static final double REPLAY_SEVERITY = 0.9;

    /**
     * Default nonce TTL. A named constant for this milestone rather than an externalized
     * property - single source of truth, to be revisited if/when configuration is needed.
     */
    public static final Duration NONCE_TTL = Duration.ofMinutes(5);

    private final ReactiveStringRedisTemplate redisTemplate;
    private final Duration nonceTtl;

    @Autowired
    public ReplayAttackDetector(ReactiveStringRedisTemplate redisTemplate) {
        this(redisTemplate, NONCE_TTL);
    }

    /**
     * Allows tests to inject a short TTL instead of waiting out the real 5-minute default.
     */
    public ReplayAttackDetector(ReactiveStringRedisTemplate redisTemplate, Duration nonceTtl) {
        this.redisTemplate = redisTemplate;
        this.nonceTtl = nonceTtl;
    }

    @Override
    public Mono<ThreatSignal> detect(SecurityAnalysisContext context) {
        String nonce = extractNonce(context);

        if (!isValidNonce(nonce)) {
            return Mono.just(cleanSignal("no usable nonce provided - replay protection not applied"));
        }

        String key = buildKey(context, nonce);

        return redisTemplate.opsForValue()
                .setIfAbsent(key, "1", nonceTtl)
                .map(claimed -> claimed
                        ? cleanSignal("nonce accepted and stored for replay protection")
                        : replaySignal(context, nonce));
    }

    private String extractNonce(SecurityAnalysisContext context) {
        List<String> values = context.headers().get(NONCE_HEADER);
        if (values == null || values.isEmpty() || values.get(0) == null) {
            return null;
        }
        return values.get(0).trim();
    }

    /**
     * Rejects missing/blank, oversized, and unsafe-character nonces without ever contacting
     * Redis - invalid input is treated the same as "no nonce provided" under the demo policy.
     */
    private boolean isValidNonce(String nonce) {
        if (nonce == null || nonce.isEmpty()) {
            return false;
        }
        if (nonce.length() > MAX_NONCE_LENGTH) {
            return false;
        }
        return SAFE_NONCE.matcher(nonce).matches();
    }

    /**
     * Scoped to method + path so the same nonce value used on a different action is not
     * treated as a replay of an unrelated request. Ordered so a future authenticated client
     * identity segment can be prepended without redesigning this detector.
     */
    private String buildKey(SecurityAnalysisContext context, String nonce) {
        return "apishield:replay:" + context.method() + ":" + context.path() + ":" + nonce;
    }

    private ThreatSignal cleanSignal(String description) {
        return new ThreatSignal(DETECTOR_NAME, false, 0.0, description);
    }

    private ThreatSignal replaySignal(SecurityAnalysisContext context, String nonce) {
        String description = "nonce '" + nonce + "' already used for " + context.method() + " " + context.path()
                + " within TTL window";
        return new ThreatSignal(DETECTOR_NAME, true, REPLAY_SEVERITY, description);
    }
}
