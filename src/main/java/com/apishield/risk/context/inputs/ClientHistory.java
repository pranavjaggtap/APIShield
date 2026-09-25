package com.apishield.risk.context.inputs;

import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInput;

import java.time.Duration;
import java.util.Objects;

/**
 * Recent traffic of one client ({@link ClientKey}) within a window: how many of its requests were
 * evaluated and how many of those were blocked. Supplied by ClientHistoryProvider (PostgreSQL) when
 * {@code apishield.risk.history-providers-enabled=true}; otherwise absent.
 */
public record ClientHistory(ClientKey clientKey, long requestsInWindow, long blockedInWindow, Duration window)
        implements ContextualInput {

    public ClientHistory {
        Objects.requireNonNull(clientKey, "clientKey");
        Objects.requireNonNull(window, "window");
        if (requestsInWindow < 0 || blockedInWindow < 0 || blockedInWindow > requestsInWindow) {
            throw new IllegalArgumentException(
                    "require 0 <= blockedInWindow <= requestsInWindow, was " + blockedInWindow + "/" + requestsInWindow);
        }
        if (window.isNegative() || window.isZero()) {
            throw new IllegalArgumentException("window must be positive");
        }
    }
}
