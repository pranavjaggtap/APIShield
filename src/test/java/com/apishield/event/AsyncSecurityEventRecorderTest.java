package com.apishield.event;

import com.apishield.context.RequestContext;
import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AsyncSecurityEventRecorderTest {

    private final SecurityEventRepository repository = mock(SecurityEventRepository.class);

    private final RequestContext request = new RequestContext("req-1", "GET", "/api/users/1", Map.of(), Map.of(),
            "127.0.0.1", Instant.parse("2026-01-01T00:00:00Z"), Optional.empty(), Optional.of("user-42"));
    private final RiskScore riskScore = RiskScore.fromSignalsOnly(0.9,
            List.of(new ThreatSignal("sql-injection", true, 0.9, "matched: tautology")));
    private final Decision decision = new Decision(Decision.Outcome.BLOCK, "blocked");

    @Test
    void savesEventBuiltFromTheDecision() {
        when(repository.save(any())).thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));
        AsyncSecurityEventRecorder recorder = new AsyncSecurityEventRecorder(repository);

        recorder.record(request, riskScore, decision);

        ArgumentCaptor<SecurityEvent> saved = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(repository, timeout(1000)).save(saved.capture());
        assertThat(saved.getValue()).isEqualTo(SecurityEvent.create(request, riskScore, decision));
        assertThat(saved.getValue().userId()).isEqualTo("user-42");
        assertThat(saved.getValue().decision()).isEqualTo("BLOCK");
    }

    @Test
    void failedSaveIsSwallowedAndReleasesItsSlot() {
        when(repository.save(any())).thenReturn(Mono.error(new RuntimeException("connection refused")));
        AsyncSecurityEventRecorder recorder = new AsyncSecurityEventRecorder(repository);

        assertThatCode(() -> recorder.record(request, riskScore, decision)).doesNotThrowAnyException();

        assertThat(recorder.inFlight()).isZero();
    }

    @Test
    void repositoryThrowingSynchronouslyIsSwallowed() {
        when(repository.save(any())).thenThrow(new IllegalStateException("no connection factory"));
        AsyncSecurityEventRecorder recorder = new AsyncSecurityEventRecorder(repository);

        assertThatCode(() -> recorder.record(request, riskScore, decision)).doesNotThrowAnyException();

        assertThat(recorder.inFlight()).isZero();
    }

    @Test
    void hangingSaveTimesOutAndReleasesItsSlot() throws InterruptedException {
        when(repository.save(any())).thenReturn(Mono.never());
        AsyncSecurityEventRecorder recorder = new AsyncSecurityEventRecorder(repository, Duration.ofMillis(50), 10);

        recorder.record(request, riskScore, decision);
        assertThat(recorder.inFlight()).isEqualTo(1);

        long deadline = System.currentTimeMillis() + 2000;
        while (recorder.inFlight() > 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        assertThat(recorder.inFlight()).isZero();
    }

    @Test
    void eventsBeyondTheInFlightLimitAreDroppedNotQueued() {
        when(repository.save(any())).thenReturn(Mono.never());
        AsyncSecurityEventRecorder recorder = new AsyncSecurityEventRecorder(repository, Duration.ofMinutes(5), 3);

        for (int i = 0; i < 10; i++) {
            recorder.record(request, riskScore, decision);
        }

        verify(repository, times(3)).save(any());
        assertThat(recorder.inFlight()).isEqualTo(3);
    }
}
