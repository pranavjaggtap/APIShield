package com.apishield.risk.factor;

import com.apishield.model.RiskAdjustment;
import com.apishield.risk.context.RiskContext;
import com.apishield.risk.context.inputs.IdentityReputation;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Weighs threat evidence by who sent the request:
 * <ul>
 *   <li>not authenticated: 1.2 - an unknown actor (a known state, not missing data). Unreachable
 *       through the gateway today, which rejects unauthenticated requests before the pipeline;</li>
 *   <li>authenticated with reputation: TRUSTED 0.85, NEUTRAL 1.0, SUSPICIOUS 1.3;</li>
 *   <li>authenticated without reputation data: missing, neutral.</li>
 * </ul>
 * Only positive evidence of trust ever dampens risk.
 */
@Component
public class IdentityRiskFactor implements RiskFactor {

    public static final String NAME = "identity";
    public static final double UNAUTHENTICATED_MULTIPLIER = 1.2;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public RiskAdjustment assess(RiskContext context) {
        Optional<String> userId = context.request().userId();
        if (userId.isEmpty()) {
            return RiskAdjustment.multiplier(NAME, UNAUTHENTICATED_MULTIPLIER, "request is not authenticated");
        }
        if (context.inputs().failed(IdentityReputation.class)) {
            return RiskAdjustment.missing(NAME, "identity reputation unavailable (provider failed)");
        }

        Optional<IdentityReputation> reputation = context.inputs().get(IdentityReputation.class)
                .filter(candidate -> candidate.userId().equals(userId.get()));
        if (reputation.isEmpty()) {
            return RiskAdjustment.missing(NAME, "no reputation data for authenticated user");
        }

        IdentityReputation.Level level = reputation.get().level();
        if (level == IdentityReputation.Level.NEUTRAL) {
            return RiskAdjustment.neutral(NAME, "authenticated user has NEUTRAL reputation");
        }
        return RiskAdjustment.multiplier(NAME, level.multiplier(), "authenticated user has " + level + " reputation");
    }
}
