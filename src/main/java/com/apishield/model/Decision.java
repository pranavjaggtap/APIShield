package com.apishield.model;

/**
 * The outcome of {@link com.apishield.decision.DecisionEngine} for a request.
 */
public record Decision(Outcome outcome, String reason) {

    /**
     * Five-tier decision model, in increasing order of risk. What APIShield currently does for each is
     * enforced in {@link com.apishield.security.SecurityGatewayFilter}. Only BLOCK stops a request today:
     * no challenge or throttling mechanism exists yet, so CHALLENGE and THROTTLE are recorded but not
     * enforced.
     */
    public enum Outcome {
        /** Low risk: the request proceeds normally. */
        ALLOW,
        /** Elevated risk: the request proceeds normally; the decision is recorded for review. */
        MONITOR,
        /** Should require additional verification. Not enforced yet - the request proceeds. */
        CHALLENGE,
        /** Should be rate-limited. Not enforced yet - the request proceeds. */
        THROTTLE,
        /** High risk: the request is rejected with 403 and never routed. */
        BLOCK
    }
}
