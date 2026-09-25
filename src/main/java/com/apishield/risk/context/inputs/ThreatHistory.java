package com.apishield.risk.context.inputs;

import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInput;

import java.time.Duration;
import java.util.Objects;

/**
 * How many of one client's ({@link ClientKey}) recent requests within a window were blocked as
 * threats. No provider supplies this yet.
 */
public record ThreatHistory(ClientKey clientKey, long recentThreatCount, Duration window) implements ContextualInput {

    public ThreatHistory {
        Objects.requireNonNull(clientKey, "clientKey");
        Objects.requireNonNull(window, "window");
        if (recentThreatCount < 0) {
            throw new IllegalArgumentException("recentThreatCount must be >= 0, was " + recentThreatCount);
        }
        if (window.isNegative() || window.isZero()) {
            throw new IllegalArgumentException("window must be positive");
        }
    }
}
