package com.apishield.risk.context;

import com.apishield.context.RequestContext;

import java.util.Locale;
import java.util.Objects;

/**
 * The identity that per-client context (history, reputation) is keyed by: the authenticated user
 * when there is one, otherwise the client IP. Deterministic - derived only from the RequestContext.
 */
public record ClientKey(Kind kind, String value) {

    public enum Kind {
        USER,
        IP
    }

    public ClientKey {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(value, "value");
        if (value.isBlank()) {
            throw new IllegalArgumentException("value must not be blank");
        }
    }

    public static ClientKey of(RequestContext request) {
        return request.userId()
                .map(userId -> new ClientKey(Kind.USER, userId))
                .orElseGet(() -> new ClientKey(Kind.IP, request.clientIp()));
    }

    /** Stable string form, e.g. {@code user:alice} or {@code ip:10.0.0.5} - suitable as a storage key. */
    public String asString() {
        return kind.name().toLowerCase(Locale.ROOT) + ":" + value;
    }
}
