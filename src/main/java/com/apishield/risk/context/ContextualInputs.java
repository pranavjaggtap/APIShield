package com.apishield.risk.context;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable, type-keyed collection of the {@link ContextualInput}s available for one request.
 * Looking inputs up by type means new kinds of context can be added without changing this class,
 * {@link RiskContext}, or the engine. Absent inputs are simply {@link Optional#empty()}.
 * <p>
 * Nothing populates inputs yet, so every request currently uses {@link #empty()}.
 */
public final class ContextualInputs {

    private static final ContextualInputs EMPTY = new ContextualInputs(Map.of());

    private final Map<Class<? extends ContextualInput>, ContextualInput> inputs;

    private ContextualInputs(Map<Class<? extends ContextualInput>, ContextualInput> inputs) {
        this.inputs = inputs;
    }

    public static ContextualInputs empty() {
        return EMPTY;
    }

    public <T extends ContextualInput> Optional<T> get(Class<T> type) {
        Objects.requireNonNull(type, "type");
        return Optional.ofNullable(inputs.get(type)).map(type::cast);
    }

    public boolean isEmpty() {
        return inputs.isEmpty();
    }

    @Override
    public String toString() {
        return "ContextualInputs" + inputs.keySet();
    }
}
