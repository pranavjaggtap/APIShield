package com.apishield.model;

import java.util.Objects;

/**
 * The effect one contextual risk factor had on a {@link RiskScore}: a multiplier applied to the
 * threat evidence (1.0 = neutral) and/or a baseline prior risk (0.0 = none), with the reason.
 * Recorded per factor so every score is explainable.
 * <p>
 * Missing data is always neutral: {@link #missing} has multiplier 1.0, prior 0.0.
 */
public record RiskAdjustment(
        String factor,
        double multiplier,
        double prior,
        Availability availability,
        String reason
) {

    public enum Availability {
        /** The factor had its data and changed the score. */
        APPLIED,
        /** The factor had its data and deliberately left the score unchanged. */
        NEUTRAL,
        /** The factor's data was unavailable; treated as neutral. */
        MISSING
    }

    public RiskAdjustment {
        Objects.requireNonNull(factor, "factor");
        Objects.requireNonNull(availability, "availability");
        Objects.requireNonNull(reason, "reason");
        if (!Double.isFinite(multiplier) || multiplier <= 0.0) {
            throw new IllegalArgumentException("multiplier must be finite and > 0, was " + multiplier);
        }
        if (!(prior >= 0.0 && prior <= 1.0)) {
            throw new IllegalArgumentException("prior must be within [0,1], was " + prior);
        }
    }

    /** The factor's data was unavailable - neutral by definition. */
    public static RiskAdjustment missing(String factor, String reason) {
        return new RiskAdjustment(factor, 1.0, 0.0, Availability.MISSING, reason);
    }

    /** The factor had its data and it called for no change. */
    public static RiskAdjustment neutral(String factor, String reason) {
        return new RiskAdjustment(factor, 1.0, 0.0, Availability.NEUTRAL, reason);
    }

    public static RiskAdjustment multiplier(String factor, double multiplier, String reason) {
        return new RiskAdjustment(factor, multiplier, 0.0, Availability.APPLIED, reason);
    }

    public static RiskAdjustment prior(String factor, double prior, String reason) {
        return new RiskAdjustment(factor, 1.0, prior, Availability.APPLIED, reason);
    }
}
