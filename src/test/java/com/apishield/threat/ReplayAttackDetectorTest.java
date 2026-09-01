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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ReplayAttackDetectorTest {

    private final ReactiveStringRedisTemplate redisTemplate = mock(ReactiveStringRedisTemplate.class);

    @SuppressWarnings("unchecked")
    private final ReactiveValueOperations<String, String> valueOperations = mock(ReactiveValueOperations.class);

    private final ReplayAttackDetector detector = new ReplayAttackDetector(redisTemplate, Duration.ofMinutes(5));

    // --- helpers -----------------------------------------------------------------------

    private static SecurityAnalysisContext context(String method, String path, String nonce) {
        Map<String, List<String>> headers = nonce == null
                ? Map.of()
                : Map.of("X-APIShield-Nonce", List.of(nonce));
        return new SecurityAnalysisContext("req-1", method, path, headers, Map.of(), "127.0.0.1", Instant.now());
    }

    private void stubOpsForValue() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    private ThreatSignal detect(SecurityAnalysisContext context) {
        return detector.detect(context).block();
    }

    // --- 1. first nonce ------------------------------------------------------------------

    @Test
    void firstUseOfNonceIsClean() {
        stubOpsForValue();
        when(valueOperations.setIfAbsent(eq("apishield:replay:GET:/api/users/1:demo-123"), eq("1"), eq(Duration.ofMinutes(5))))
                .thenReturn(Mono.just(true));

        ThreatSignal signal = detect(context("GET", "/api/users/1", "demo-123"));

        assertThat(signal.threatDetected()).isFalse();
        assertThat(signal.severity()).isEqualTo(0.0);
        assertThat(signal.detectorName()).isEqualTo("replay-attack");
    }

    // --- 2. reused nonce -------------------------------------------------------------------

    @Test
    void reusedNonceIsReplayThreat() {
        stubOpsForValue();
        when(valueOperations.setIfAbsent(eq("apishield:replay:GET:/api/users/1:demo-123"), eq("1"), any(Duration.class)))
                .thenReturn(Mono.just(false));

        ThreatSignal signal = detect(context("GET", "/api/users/1", "demo-123"));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.9);
        assertThat(signal.description()).contains("demo-123");
    }

    // --- 3. different nonce ------------------------------------------------------------------

    @Test
    void differentNonceIsClean() {
        stubOpsForValue();
        when(valueOperations.setIfAbsent(eq("apishield:replay:GET:/api/users/1:other-nonce"), eq("1"), any(Duration.class)))
                .thenReturn(Mono.just(true));

        ThreatSignal signal = detect(context("GET", "/api/users/1", "other-nonce"));

        assertThat(signal.threatDetected()).isFalse();
    }

    // --- 4. missing nonce ----------------------------------------------------------------------

    @Test
    void missingNonceIsCleanAndRedisNotContacted() {
        ThreatSignal signal = detect(context("GET", "/api/users/1", null));

        assertThat(signal.threatDetected()).isFalse();
        assertThat(signal.severity()).isEqualTo(0.0);
        verifyNoInteractions(redisTemplate);
    }

    // --- 5. blank nonce -----------------------------------------------------------------------

    @Test
    void blankNonceIsCleanAndRedisNotContacted() {
        ThreatSignal signal = detect(context("GET", "/api/users/1", "   "));

        assertThat(signal.threatDetected()).isFalse();
        verifyNoInteractions(redisTemplate);
    }

    // --- 6. oversized nonce ---------------------------------------------------------------------

    @Test
    void oversizedNonceIsCleanAndRedisNotContacted() {
        String longNonce = "a".repeat(257);

        ThreatSignal signal = detect(context("GET", "/api/users/1", longNonce));

        assertThat(signal.threatDetected()).isFalse();
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void nonceAtMaxLengthIsStillValidAndReachesRedis() {
        stubOpsForValue();
        String maxNonce = "a".repeat(256);
        when(valueOperations.setIfAbsent(eq("apishield:replay:GET:/api/users/1:" + maxNonce), eq("1"), any(Duration.class)))
                .thenReturn(Mono.just(true));

        ThreatSignal signal = detect(context("GET", "/api/users/1", maxNonce));

        assertThat(signal.threatDetected()).isFalse();
        verify(valueOperations).setIfAbsent(eq("apishield:replay:GET:/api/users/1:" + maxNonce), eq("1"), any(Duration.class));
    }

    // --- 7. invalid characters ------------------------------------------------------------------

    @Test
    void invalidCharactersAreCleanAndRedisNotContacted() {
        ThreatSignal signal = detect(context("GET", "/api/users/1", "nonce with spaces!"));

        assertThat(signal.threatDetected()).isFalse();
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void nonceWithAngleBracketIsCleanAndRedisNotContacted() {
        ThreatSignal signal = detect(context("GET", "/api/users/1", "nonce<script>"));

        assertThat(signal.threatDetected()).isFalse();
        verifyNoInteractions(redisTemplate);
    }

    // --- 8. case sensitivity --------------------------------------------------------------------

    @Test
    void nonceComparisonIsCaseSensitive() {
        stubOpsForValue();
        when(valueOperations.setIfAbsent(eq("apishield:replay:GET:/api/users/1:Demo-123"), eq("1"), any(Duration.class)))
                .thenReturn(Mono.just(true));
        when(valueOperations.setIfAbsent(eq("apishield:replay:GET:/api/users/1:demo-123"), eq("1"), any(Duration.class)))
                .thenReturn(Mono.just(true));

        detect(context("GET", "/api/users/1", "Demo-123"));
        detect(context("GET", "/api/users/1", "demo-123"));

        verify(valueOperations).setIfAbsent(eq("apishield:replay:GET:/api/users/1:Demo-123"), eq("1"), any(Duration.class));
        verify(valueOperations).setIfAbsent(eq("apishield:replay:GET:/api/users/1:demo-123"), eq("1"), any(Duration.class));
    }

    // --- 9. different method/path produce different keys -----------------------------------------

    @Test
    void sameNonceDifferentMethodProducesDifferentKeys() {
        stubOpsForValue();
        when(valueOperations.setIfAbsent(any(), eq("1"), any(Duration.class))).thenReturn(Mono.just(true));

        detect(context("GET", "/api/users/1", "demo-123"));
        detect(context("POST", "/api/users/1", "demo-123"));

        verify(valueOperations).setIfAbsent(eq("apishield:replay:GET:/api/users/1:demo-123"), eq("1"), any(Duration.class));
        verify(valueOperations).setIfAbsent(eq("apishield:replay:POST:/api/users/1:demo-123"), eq("1"), any(Duration.class));
    }

    @Test
    void sameNonceDifferentPathProducesDifferentKeys() {
        stubOpsForValue();
        when(valueOperations.setIfAbsent(any(), eq("1"), any(Duration.class))).thenReturn(Mono.just(true));

        detect(context("GET", "/api/users/1", "demo-123"));
        detect(context("GET", "/api/users/2", "demo-123"));

        verify(valueOperations).setIfAbsent(eq("apishield:replay:GET:/api/users/1:demo-123"), eq("1"), any(Duration.class));
        verify(valueOperations).setIfAbsent(eq("apishield:replay:GET:/api/users/2:demo-123"), eq("1"), any(Duration.class));
    }

    // --- 10. Redis error propagation (fail-closed relies on this NOT being swallowed) -------------

    @Test
    void redisErrorPropagatesRatherThanBeingSwallowed() {
        stubOpsForValue();
        when(valueOperations.setIfAbsent(any(), eq("1"), any(Duration.class)))
                .thenReturn(Mono.error(new RuntimeException("redis unreachable")));

        StepVerifier.create(detector.detect(context("GET", "/api/users/1", "demo-123")))
                .expectErrorMatches(ex -> ex instanceof RuntimeException && ex.getMessage().equals("redis unreachable"))
                .verify();
    }

    // --- 11. reactive behavior -----------------------------------------------------------------------

    @Test
    void detectReturnsReactiveMonoForCleanCase() {
        StepVerifier.create(detector.detect(context("GET", "/api/users/1", null)))
                .assertNext(signal -> assertThat(signal.threatDetected()).isFalse())
                .verifyComplete();
    }

    @Test
    void alwaysReturnsExactlyOneSignalForValidNonce() {
        stubOpsForValue();
        when(valueOperations.setIfAbsent(any(), eq("1"), any(Duration.class))).thenReturn(Mono.just(true));

        StepVerifier.create(detector.detect(context("GET", "/api/users/1", "demo-123")))
                .expectNextCount(1)
                .verifyComplete();
    }
}
