package com.apishield.risk.context.inputs;

import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInput;

import java.time.Duration;
import java.util.Objects;

/**
 * How many of one client's ({@link ClientKey}) recent requests within a window carried detector evidence
 * at or above the BLOCK threshold (detector-only threat score, before context). Supplied by ThreatHistoryProvider (PostgreSQL) when
 * {@code apishield.risk.history-providers-enabled=true}; otherwise absent.
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
