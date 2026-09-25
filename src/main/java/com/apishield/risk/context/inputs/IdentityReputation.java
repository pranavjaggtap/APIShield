package com.apishield.risk.context.inputs;

import com.apishield.risk.context.ContextualInput;

import java.util.Objects;

/**
 * Reputation of an authenticated user. No provider supplies this yet (there is no reputation data
 * source), so it is currently always missing - and missing reputation is neutral.
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
