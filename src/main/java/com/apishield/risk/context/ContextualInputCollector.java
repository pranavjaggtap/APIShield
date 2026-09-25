package com.apishield.risk.context;

import com.apishield.context.RequestContext;
import com.apishield.risk.RiskEngineProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Gathers every {@link ContextualInputProvider}'s input for a request, before scoring. Providers run
 * in parallel, each bounded by a timeout.
 * <p>
 * Never fails and never blocks a request: a provider that errors, times out, returns the wrong type or
 * throws is recorded as a failed (missing) input, making the context {@link ContextualInputs#degraded()}.
 * A provider with no data (empty) is simply missing, not degraded.
 */
@Component
public class ContextualInputCollector {

    public static final Duration DEFAULT_TIMEOUT = Duration.ofMillis(100);

    private static final Logger log = LoggerFactory.getLogger(ContextualInputCollector.class);

    private final List<ContextualInputProvider<?>> providers;
    private final Duration timeout;

    @Autowired
    public ContextualInputCollector(List<ContextualInputProvider<?>> providers, RiskEngineProperties properties) {
        this(providers, properties.providerTimeout());
    }

    public ContextualInputCollector(List<ContextualInputProvider<?>> providers, Duration timeout) {
        this.providers = List.copyOf(providers);
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        Set<Class<?>> types = new HashSet<>();
        for (ContextualInputProvider<?> provider : this.providers) {
            if (!types.add(provider.type())) {
                throw new IllegalStateException("More than one ContextualInputProvider for " + provider.type().getName());
            }
        }
    }

    /** A collector with no providers - every request gets empty, non-degraded inputs. */
    public static ContextualInputCollector none() {
        return new ContextualInputCollector(List.of(), DEFAULT_TIMEOUT);
    }

    public Mono<ContextualInputs> collect(RequestContext request) {
        if (providers.isEmpty()) {
            return Mono.just(ContextualInputs.empty());
        }
        return Flux.fromIterable(providers)
                .flatMap(provider -> collectOne(provider, request))
                .collectList()
                .map(contributions -> {
                    ContextualInputs.Builder builder = ContextualInputs.builder();
                    contributions.forEach(contribution -> contribution.accept(builder));
                    return builder.build();
                })
                .onErrorResume(error -> {
                    // Last resort - per-provider failures are already handled above.
                    log.error("Contextual input collection failed for request {} - all inputs treated as missing: {}",
                            request.requestId(), error.toString());
                    ContextualInputs.Builder builder = ContextualInputs.builder();
                    providers.forEach(provider -> builder.markFailed(provider.type()));
                    return Mono.just(builder.build());
                });
    }

    private <T extends ContextualInput> Mono<Consumer<ContextualInputs.Builder>> collectOne(
            ContextualInputProvider<T> provider, RequestContext request) {
        Class<T> type = provider.type();
        return Mono.defer(() -> provider.provide(request))
                .timeout(timeout)
                .<Consumer<ContextualInputs.Builder>>map(value -> {
                    T checked = type.cast(value); // eager, so a wrong type is handled below like any failure
                    return builder -> builder.put(type, checked);
                })
                .defaultIfEmpty(builder -> { })
                .onErrorResume(error -> {
                    log.warn("Contextual input {} unavailable for request {} - treated as missing: {}",
                            type.getSimpleName(), request.requestId(), error.toString());
                    return Mono.just(builder -> builder.markFailed(type));
                });
    }
}
