package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies real Redis behavior that cannot be meaningfully proven with a mock: TTL expiry
 * and genuine atomicity under concurrency. Skipped by default so {@code ./mvnw test} never
 * requires a running Redis instance; run explicitly with
 * {@code REDIS_INTEGRATION_TEST=true ./mvnw test} against a reachable Redis, consistent with
 * {@link com.apishield.RedisConnectivityTest}.
 */
@SpringBootTest
@EnabledIfEnvironmentVariable(named = "REDIS_INTEGRATION_TEST", matches = "true")
class ReplayAttackDetectorIntegrationTest {

    @Autowired
    private ReactiveStringRedisTemplate redisTemplate;

    private static SecurityAnalysisContext context(String nonce) {
        return new SecurityAnalysisContext(
                "req-1", "GET", "/api/replay-integration-test",
                Map.of("X-APIShield-Nonce", List.of(nonce)), Map.of(), "127.0.0.1", Instant.now());
    }

    @Test
    void nonceCanBeReusedAfterTtlExpires() throws InterruptedException {
        ReplayAttackDetector detector = new ReplayAttackDetector(redisTemplate, Duration.ofSeconds(2));
        String nonce = "ttl-test-" + UUID.randomUUID();
        SecurityAnalysisContext context = context(nonce);

        ThreatSignal first = detector.detect(context).block();
        assertThat(first.threatDetected()).isFalse();

        ThreatSignal immediateReplay = detector.detect(context).block();
        assertThat(immediateReplay.threatDetected()).isTrue();

        Thread.sleep(2500);

        ThreatSignal afterExpiry = detector.detect(context).block();
        assertThat(afterExpiry.threatDetected()).isFalse();
    }

    @Test
    void onlyOneOfManyConcurrentIdenticalNoncesIsAccepted() {
        ReplayAttackDetector detector = new ReplayAttackDetector(redisTemplate, Duration.ofMinutes(1));
        String nonce = "concurrency-test-" + UUID.randomUUID();
        SecurityAnalysisContext context = context(nonce);

        AtomicLong acceptedCount = new AtomicLong();

        StepVerifier.create(
                        Flux.range(0, 20)
                                .flatMap(i -> detector.detect(context))
                                .doOnNext(signal -> {
                                    if (!signal.threatDetected()) {
                                        acceptedCount.incrementAndGet();
                                    }
                                }))
                .expectNextCount(20)
                .verifyComplete();

        assertThat(acceptedCount.get()).isEqualTo(1);
    }
}
