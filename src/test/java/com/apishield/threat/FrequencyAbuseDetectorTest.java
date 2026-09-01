package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.ReactiveValueOperations;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class FrequencyAbuseDetectorTest {

    private static final Duration TEST_WINDOW = Duration.ofSeconds(60);
    private static final long TEST_THRESHOLD = 20L;

    private final ReactiveStringRedisTemplate redisTemplate = mock(ReactiveStringRedisTemplate.class);

    @SuppressWarnings("unchecked")
    private final ReactiveValueOperations<String, String> valueOperations = mock(ReactiveValueOperations.class);

    private final FrequencyAbuseDetector detector =
            new FrequencyAbuseDetector(redisTemplate, TEST_WINDOW, TEST_THRESHOLD);

    // --- helpers -----------------------------------------------------------------------

    private static SecurityAnalysisContext context(String clientIp, String... xForwardedFor) {
        Map<String, List<String>> headers = xForwardedFor.length == 0
                ? Map.of()
                : Map.of("X-Forwarded-For", List.of(xForwardedFor));
        return new SecurityAnalysisContext("req-1", "GET", "/api/users/1", headers, Map.of(), clientIp, Instant.now());
    }

    private void stubOpsForValue() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    private void stubIncrement(String key, long returnedCount) {
        when(valueOperations.increment(eq(key))).thenReturn(Mono.just(returnedCount));
    }

    private void stubExpire(String key) {
        when(redisTemplate.expire(eq(key), any(Duration.class))).thenReturn(Mono.just(true));
    }

    private ThreatSignal detect(SecurityAnalysisContext context) {
        return detector.detect(context).block();
    }

    // --- below threshold -----------------------------------------------------------------

    @Test
    void belowThresholdIsClean() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:127.0.0.1", 5L);

        ThreatSignal signal = detect(context("127.0.0.1"));

        assertThat(signal.threatDetected()).isFalse();
        assertThat(signal.severity()).isEqualTo(0.0);
        assertThat(signal.detectorName()).isEqualTo("frequency-abuse");
    }

    // --- exactly threshold -----------------------------------------------------------------

    @Test
    void exactlyThresholdIsThreat() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:127.0.0.1", TEST_THRESHOLD);

        ThreatSignal signal = detect(context("127.0.0.1"));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.9);
        assertThat(signal.description()).contains("127.0.0.1");
    }

    // --- above threshold -----------------------------------------------------------------

    @Test
    void aboveThresholdIsThreat() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:127.0.0.1", TEST_THRESHOLD + 5);

        ThreatSignal signal = detect(context("127.0.0.1"));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.9);
    }

    // --- expected Redis key -----------------------------------------------------------------

    @Test
    void usesExpectedRedisKey() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:192.168.1.50", 1L);
        stubExpire("apishield:frequency:192.168.1.50");

        detect(context("192.168.1.50"));

        verify(valueOperations).increment(eq("apishield:frequency:192.168.1.50"));
    }

    // --- expire only when count == 1 -----------------------------------------------------------

    @Test
    void expireIsCalledOnFirstRequestOfWindow() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:127.0.0.1", 1L);
        stubExpire("apishield:frequency:127.0.0.1");

        detect(context("127.0.0.1"));

        verify(redisTemplate).expire(eq("apishield:frequency:127.0.0.1"), eq(TEST_WINDOW));
    }

    @Test
    void expireIsNotCalledOnSubsequentRequestsInSameWindow() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:127.0.0.1", 7L);

        detect(context("127.0.0.1"));

        verify(redisTemplate, never()).expire(any(), any());
    }

    // --- different client identities -----------------------------------------------------------

    @Test
    void differentClientIdentitiesUseSeparateCounters() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:10.0.0.1", 1L);
        stubIncrement("apishield:frequency:10.0.0.2", 1L);
        stubExpire("apishield:frequency:10.0.0.1");
        stubExpire("apishield:frequency:10.0.0.2");

        detect(context("10.0.0.1"));
        detect(context("10.0.0.2"));

        verify(valueOperations).increment(eq("apishield:frequency:10.0.0.1"));
        verify(valueOperations).increment(eq("apishield:frequency:10.0.0.2"));
    }

    // --- unknown identity is counted, not exempted -----------------------------------------------

    @Test
    void unknownIdentityIsCountedNotExempted() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:unknown", TEST_THRESHOLD);

        ThreatSignal signal = detect(context("unknown"));

        assertThat(signal.threatDetected()).isTrue();
        verify(valueOperations).increment(eq("apishield:frequency:unknown"));
    }

    @Test
    void blankClientIpFallsBackToUnknownAndIsStillCounted() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:unknown", 1L);
        stubExpire("apishield:frequency:unknown");

        detect(context(""));

        verify(valueOperations).increment(eq("apishield:frequency:unknown"));
    }

    // --- X-Forwarded-For is ignored for identity -------------------------------------------------

    @Test
    void xForwardedForIsIgnoredForClientIdentity() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:127.0.0.1", 1L);
        stubExpire("apishield:frequency:127.0.0.1");

        // Same real clientIp, wildly different (spoofable) X-Forwarded-For values.
        detect(context("127.0.0.1", "1.2.3.4"));
        detect(context("127.0.0.1", "9.9.9.9"));

        verify(valueOperations, org.mockito.Mockito.times(2)).increment(eq("apishield:frequency:127.0.0.1"));
    }

    // --- IPv4 / IPv6 -----------------------------------------------------------------------------

    @Test
    void ipv4AddressUsedAsKeyComponent() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:203.0.113.7", 3L);

        ThreatSignal signal = detect(context("203.0.113.7"));

        assertThat(signal.threatDetected()).isFalse();
        verify(valueOperations).increment(eq("apishield:frequency:203.0.113.7"));
    }

    @Test
    void ipv6AddressUsedAsKeyComponent() {
        String ipv6 = "2001:db8:85a3:0:0:8a2e:370:7334";
        stubOpsForValue();
        stubIncrement("apishield:frequency:" + ipv6, 3L);

        ThreatSignal signal = detect(context(ipv6));

        assertThat(signal.threatDetected()).isFalse();
        verify(valueOperations).increment(eq("apishield:frequency:" + ipv6));
    }

    // --- Redis error propagation -------------------------------------------------------------------

    @Test
    void redisErrorFromIncrementPropagates() {
        stubOpsForValue();
        when(valueOperations.increment(any())).thenReturn(Mono.error(new RuntimeException("redis unreachable")));

        StepVerifier.create(detector.detect(context("127.0.0.1")))
                .expectErrorMatches(ex -> ex instanceof RuntimeException && ex.getMessage().equals("redis unreachable"))
                .verify();
    }

    @Test
    void redisErrorFromExpirePropagates() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:127.0.0.1", 1L);
        when(redisTemplate.expire(any(), any(Duration.class)))
                .thenReturn(Mono.error(new RuntimeException("redis unreachable during expire")));

        StepVerifier.create(detector.detect(context("127.0.0.1")))
                .expectErrorMatches(ex -> ex instanceof RuntimeException
                        && ex.getMessage().equals("redis unreachable during expire"))
                .verify();
    }

    // --- reactive behavior -----------------------------------------------------------------------------

    @Test
    void detectReturnsReactiveMono() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:127.0.0.1", 1L);
        stubExpire("apishield:frequency:127.0.0.1");

        StepVerifier.create(detector.detect(context("127.0.0.1")))
                .assertNext(signal -> assertThat(signal.threatDetected()).isFalse())
                .verifyComplete();
    }

    @Test
    void alwaysReturnsExactlyOneSignal() {
        stubOpsForValue();
        stubIncrement("apishield:frequency:127.0.0.1", 1L);
        stubExpire("apishield:frequency:127.0.0.1");

        StepVerifier.create(detector.detect(context("127.0.0.1")))
                .expectNextCount(1)
                .verifyComplete();
    }
}
