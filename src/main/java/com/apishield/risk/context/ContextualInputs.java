package com.apishield.risk.context;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable, type-keyed collection of the {@link ContextualInput}s gathered for one request by
 * {@link ContextualInputCollector}. Looking inputs up by type means new kinds of context can be
 * added without changing this class, {@link RiskContext}, or the engine.
 * <p>
 * An input can be absent for two reasons, both treated as neutral by the risk factors:
 * <ul>
 *   <li>its provider had no data for this request (normal - e.g. an unconfigured route);</li>
 *   <li>its provider failed or timed out - recorded in {@link #failedTypes()}, which makes the
 *       context {@link #degraded()} so the resulting score can be flagged as computed on partial data.</li>
 * </ul>
 */
public final class ContextualInputs {

    private static final ContextualInputs EMPTY = new ContextualInputs(Map.of(), Set.of());

    private final Map<Class<? extends ContextualInput>, ContextualInput> inputs;
    private final Set<Class<? extends ContextualInput>> failedTypes;

    private ContextualInputs(Map<Class<? extends ContextualInput>, ContextualInput> inputs,
                             Set<Class<? extends ContextualInput>> failedTypes) {
        this.inputs = inputs;
        this.failedTypes = failedTypes;
    }

    public static ContextualInputs empty() {
        return EMPTY;
    }

    public static Builder builder() {
        return new Builder();
    }

    public <T extends ContextualInput> Optional<T> get(Class<T> type) {
        Objects.requireNonNull(type, "type");
        return Optional.ofNullable(inputs.get(type)).map(type::cast);
    }

    /** True if the provider for this input type failed or timed out for this request. */
    public boolean failed(Class<? extends ContextualInput> type) {
        return failedTypes.contains(type);
    }

    public Set<Class<? extends ContextualInput>> failedTypes() {
        return failedTypes;
    }

    /** True if any contextual input is missing because its provider failed or timed out. */
    public boolean degraded() {
        return !failedTypes.isEmpty();
    }

    public boolean isEmpty() {
        return inputs.isEmpty();
    }

    @Override
    public String toString() {
        return "ContextualInputs" + inputs.keySet() + (degraded() ? " failed" + failedTypes : "");
    }

    public static final class Builder {

        private final Map<Class<? extends ContextualInput>, ContextualInput> inputs = new HashMap<>();
        private final Set<Class<? extends ContextualInput>> failedTypes = new HashSet<>();

        private Builder() {
        }

        public <T extends ContextualInput> Builder put(Class<T> type, T value) {
            Objects.requireNonNull(type, "type");
            inputs.put(type, type.cast(Objects.requireNonNull(value, "value")));
            failedTypes.remove(type);
            return this;
        }

        public Builder markFailed(Class<? extends ContextualInput> type) {
            Objects.requireNonNull(type, "type");
            inputs.remove(type);
            failedTypes.add(type);
            return this;
        }

        public ContextualInputs build() {
            if (inputs.isEmpty() && failedTypes.isEmpty()) {
                return EMPTY;
            }
            return new ContextualInputs(Map.copyOf(inputs), Set.copyOf(failedTypes));
        }
    }
}
