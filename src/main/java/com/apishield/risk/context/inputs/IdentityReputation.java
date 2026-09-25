package com.apishield.risk.context.inputs;

import com.apishield.risk.context.ContextualInput;

import java.util.Objects;

/**
 * Reputation of an authenticated user. Deliberately has no provider: APIShield has no authoritative
 * identity-reputation source, and none is derived from its own security events (that history is covered,
 * with its limitations, by ClientHistory/ThreatHistory). It is therefore always missing - and missing
 * reputation is neutral. A provider should only be added for a real external source (e.g. an IdP or
 * fraud-scoring service).
 */
public record IdentityReputation(String userId, Level level) implements ContextualInput {

    /** Multipliers from the contextual risk design. Only positive evidence of trust may dampen risk. */
    public enum Level {
        TRUSTED(0.85),
        NEUTRAL(1.0),
        SUSPICIOUS(1.3);

        private final double multiplier;

        Level(double multiplier) {
            this.multiplier = multiplier;
        }

        public double multiplier() {
            return multiplier;
        }
    }

    public IdentityReputation {
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(level, "level");
    }
}
