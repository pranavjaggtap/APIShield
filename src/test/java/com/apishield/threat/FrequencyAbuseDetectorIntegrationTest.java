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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies real Redis behavior that cannot be meaningfully proven with a mock: genuine
 * atomicity under concurrency and real TTL expiry. Skipped by default so {@code ./mvnw test}
 * never requires a running Redis instance; run explicitly with
 * {@code REDIS_INTEGRATION_TEST=true ./mvnw test} against a reachable Redis, consistent with
 * {@link com.apishield.RedisConnectivityTest} and {@link ReplayAttackDetectorIntegrationTest}.
 */
@SpringBootTest
@EnabledIfEnvironmentVariable(named = "REDIS_INTEGRATION_TEST", matches = "true")
class FrequencyAbuseDetectorIntegrationTest {

    @Autowired
    private ReactiveStringRedisTemplate redisTemplate;

    private static SecurityAnalysisContext context(String clientIp) {
        return new SecurityAnalysisContext(
                "req-1", "GET", "/api/frequency-integration-test", Map.of(), Map.of(), clientIp, Instant.now());
    }

    @Test
    void counterIncrementsAcrossRepeatedRequests() {
        FrequencyAbuseDetector detector = new FrequencyAbuseDetector(redisTemplate, Duration.ofMinutes(1), 100L);
        String clientId = "counter-test-" + UUID.randomUUID();

        for (int i = 1; i <= 5; i++) {
            ThreatSignal signal = detector.detect(context(clientId)).block();
            assertThat(signal.threatDetected()).isFalse();
            assertThat(signal.description()).contains(String.valueOf(i));
        }
    }

    @Test
    void thresholdBehaviorAgainstRealRedis() {
        long threshold = 5L;
        FrequencyAbuseDetector detector = new FrequencyAbuseDetector(redisTemplate, Duration.ofMinutes(1), threshold);
        String clientId = "threshold-test-" + UUID.randomUUID();

        ThreatSignal lastSignal = null;
        for (int i = 1; i <= threshold; i++) {
            lastSignal = detector.detect(context(clientId)).block();
        }

        assertThat(lastSignal.threatDetected()).isTrue();
        assertThat(lastSignal.severity()).isEqualTo(0.9);
    }

    @Test
    void separateClientsHaveIndependentCounters() {
        FrequencyAbuseDetector detector = new FrequencyAbuseDetector(redisTemplate, Duration.ofMinutes(1), 3L);
        String clientA = "client-a-" + UUID.randomUUID();
        String clientB = "client-b-" + UUID.randomUUID();

        detector.detect(context(clientA)).block();
        detector.detect(context(clientA)).block();
        ThreatSignal bFirst = detector.detect(context(clientB)).block();

        assertThat(bFirst.threatDetected()).isFalse();
        assertThat(bFirst.description()).contains("1 request");
    }

    @Test
    void expirationResetsCounterAfterWindow() throws InterruptedException {
        FrequencyAbuseDetector detector = new FrequencyAbuseDetector(redisTemplate, Duration.ofSeconds(2), 3L);
        String clientId = "expiry-test-" + UUID.randomUUID();

        detector.detect(context(clientId)).block();
        detector.detect(context(clientId)).block();
        ThreatSignal thirdInWindow = detector.detect(context(clientId)).block();
        assertThat(thirdInWindow.threatDetected()).isTrue();

        Thread.sleep(2500);

        ThreatSignal afterExpiry = detector.detect(context(clientId)).block();
        assertThat(afterExpiry.threatDetected()).isFalse();
        assertThat(afterExpiry.description()).contains("1 request");
    }

    @Test
    void concurrentRequestsProduceNoLostIncrements() {
        FrequencyAbuseDetector detector = new FrequencyAbuseDetector(redisTemplate, Duration.ofMinutes(1), 1000L);
        String clientId = "concurrency-test-" + UUID.randomUUID();
        int concurrentRequests = 50;

        StepVerifier.create(
                        Flux.range(0, concurrentRequests)
                                .flatMap(i -> detector.detect(context(clientId))))
                .expectNextCount(concurrentRequests)
                .verifyComplete();

        ThreatSignal finalSignal = detector.detect(context(clientId)).block();
        assertThat(finalSignal.description()).contains(String.valueOf(concurrentRequests + 1));
    }
}
