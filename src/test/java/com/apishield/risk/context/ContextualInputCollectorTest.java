package com.apishield.risk.context;

import com.apishield.context.RequestContext;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.inputs.ClientHistory;
import com.apishield.risk.context.inputs.RouteProfile;
import com.apishield.risk.context.inputs.ThreatHistory;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.List;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContextualInputCollectorTest {

    private static final RequestContext REQUEST = RiskTestContexts.authenticated("alice");
    private static final RouteProfile PROFILE = new RouteProfile("user-service", RouteProfile.Sensitivity.HIGH);
    private static final ThreatHistory HISTORY =
            new ThreatHistory(new ClientKey(ClientKey.Kind.USER, "alice"), 2, Duration.ofHours(1));

    private static <T extends ContextualInput> ContextualInputProvider<T> provider(
            Class<T> type, Function<RequestContext, Mono<T>> behavior) {
        return new ContextualInputProvider<>() {
            @Override
            public Class<T> type() {
                return type;
            }

            @Override
            public Mono<T> provide(RequestContext request) {
                return behavior.apply(request);
            }
        };
    }

    private static ContextualInputs collect(ContextualInputCollector collector) {
        return collector.collect(REQUEST).block(Duration.ofSeconds(5));
    }

    @Test
    void noProvidersYieldsEmptyNonDegradedInputs() {
        ContextualInputs inputs = collect(ContextualInputCollector.none());

        assertThat(inputs.isEmpty()).isTrue();
        assertThat(inputs.degraded()).isFalse();
    }

    @Test
    void providedValuesAreCollected() {
        ContextualInputCollector collector = new ContextualInputCollector(List.of(
                provider(RouteProfile.class, request -> Mono.just(PROFILE)),
                provider(ThreatHistory.class, request -> Mono.just(HISTORY))), Duration.ofSeconds(1));

        ContextualInputs inputs = collect(collector);

        assertThat(inputs.get(RouteProfile.class)).contains(PROFILE);
        assertThat(inputs.get(ThreatHistory.class)).contains(HISTORY);
        assertThat(inputs.degraded()).isFalse();
    }

    @Test
    void emptyProviderIsMissingButNotDegraded() {
        ContextualInputCollector collector = new ContextualInputCollector(List.of(
                provider(RouteProfile.class, request -> Mono.empty())), Duration.ofSeconds(1));

        ContextualInputs inputs = collect(collector);

        assertThat(inputs.get(RouteProfile.class)).isEmpty();
        assertThat(inputs.failed(RouteProfile.class)).isFalse();
        assertThat(inputs.degraded()).isFalse();
    }

    @Test
    void failingProviderBecomesMissingAndDegradedWithoutAffectingOthers() {
        ContextualInputCollector collector = new ContextualInputCollector(List.of(
                provider(RouteProfile.class, request -> Mono.just(PROFILE)),
                provider(ThreatHistory.class, request -> Mono.error(new IllegalStateException("redis down")))),
                Duration.ofSeconds(1));

        ContextualInputs inputs = collect(collector);

        assertThat(inputs.get(RouteProfile.class)).contains(PROFILE);
        assertThat(inputs.get(ThreatHistory.class)).isEmpty();
        assertThat(inputs.failed(ThreatHistory.class)).isTrue();
        assertThat(inputs.degraded()).isTrue();
    }

    @Test
    void providerThrowingSynchronouslyBecomesMissingAndDegraded() {
        ContextualInputCollector collector = new ContextualInputCollector(List.of(
                provider(ThreatHistory.class, request -> {
                    throw new IllegalStateException("bug");
                })), Duration.ofSeconds(1));

        ContextualInputs inputs = collect(collector);

        assertThat(inputs.failed(ThreatHistory.class)).isTrue();
        assertThat(inputs.degraded()).isTrue();
    }

    @Test
    void slowProviderTimesOutAndBecomesMissingAndDegraded() {
        ContextualInputCollector collector = new ContextualInputCollector(List.of(
                provider(ClientHistory.class, request -> Mono.never())), Duration.ofMillis(100));

        StepVerifier.withVirtualTime(() -> collector.collect(REQUEST))
                .thenAwait(Duration.ofMillis(100))
                .assertNext(inputs -> {
                    assertThat(inputs.failed(ClientHistory.class)).isTrue();
                    assertThat(inputs.degraded()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void providersRunInParallel() {
        ContextualInputCollector collector = new ContextualInputCollector(List.of(
                provider(RouteProfile.class, request -> Mono.delay(Duration.ofMillis(80)).thenReturn(PROFILE)),
                provider(ThreatHistory.class, request -> Mono.delay(Duration.ofMillis(80)).thenReturn(HISTORY))),
                Duration.ofMillis(100));

        // Sequentially these would need 160ms and the second would exceed its 100ms budget.
        StepVerifier.withVirtualTime(() -> collector.collect(REQUEST))
                .thenAwait(Duration.ofMillis(80))
                .assertNext(inputs -> {
                    assertThat(inputs.get(RouteProfile.class)).contains(PROFILE);
                    assertThat(inputs.get(ThreatHistory.class)).contains(HISTORY);
                    assertThat(inputs.degraded()).isFalse();
                })
                .verifyComplete();
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void valueOfTheWrongTypeBecomesMissingAndDegraded() {
        ContextualInputProvider raw = provider(ThreatHistory.class, request -> (Mono) Mono.just(PROFILE));
        ContextualInputCollector collector = new ContextualInputCollector(List.of(raw), Duration.ofSeconds(1));

        ContextualInputs inputs = collect(collector);

        assertThat(inputs.get(ThreatHistory.class)).isEmpty();
        assertThat(inputs.degraded()).isTrue();
    }

    @Test
    void duplicateProvidersForOneTypeAreRejected() {
        assertThatThrownBy(() -> new ContextualInputCollector(List.of(
                provider(RouteProfile.class, request -> Mono.empty()),
                provider(RouteProfile.class, request -> Mono.empty())), Duration.ofSeconds(1)))
                .isInstanceOf(IllegalStateException.class);
    }
}
