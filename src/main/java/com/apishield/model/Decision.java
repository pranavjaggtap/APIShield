package com.apishield.model;

/**
 * The outcome of {@link com.apishield.decision.DecisionEngine} for a request.
 */
public record Decision(Outcome outcome, String reason) {

    public enum Outcome {
        ALLOW,
        BLOCK
    }
}
