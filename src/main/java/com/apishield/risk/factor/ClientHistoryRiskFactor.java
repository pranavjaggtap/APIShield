package com.apishield.risk.factor;

import com.apishield.model.RiskAdjustment;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.RiskContext;
import com.apishield.risk.context.inputs.ClientHistory;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * PROVISIONAL PLACEHOLDER (Phase 2). Proposes a baseline prior from the share of a client's recent
 * requests that were blocked: {@code prior = MAX_PRIOR * blocked / requests}, once at least
 * {@link #MIN_SAMPLE} requests are known.
 * <p>
 * The contextual risk design specified the threat-history prior but left client-history numbers open;
 * {@code MAX_PRIOR = 0.30} and {@code MIN_SAMPLE = 10} are unvalidated proposals, not derived from data.
 * <p>
 * Safety: this factor's prior is NOT inherently below the ALLOW/BLOCK threshold. The engine amplifies
 * evidence - priors included - by the context multiplier, so a 0.30 prior on a CRITICAL route (x2.0)
 * scores {@code 1 - 0.7^2 = 0.51} for a request that carries no threat at all, which would BLOCK. What
 * keeps it safe is that contextual priors are disabled by default
 * ({@code apishield.risk.contextual-priors-enabled=false}): while disabled the engine records the
 * proposed prior but applies 0. {@link ClientHistory} is supplied by ClientHistoryProvider only when
 * {@code apishield.risk.history-providers-enabled=true} (default false); otherwise this factor is MISSING.
 * <p>
 * Open requirements - a PostgreSQL ClientHistoryProvider now exists (opt-in), so these must be resolved
 * before contextual priors are enabled:
 * <ul>
 *   <li><b>Double counting:</b> this factor and {@link ThreatHistoryRiskFactor} are both derived from
 *       blocked requests, yet the engine combines their priors as independent evidence (noisy-OR), so the
 *       same history counts twice.</li>
 *   <li><b>Feedback loop:</b> a request blocked partly because of a prior raises the blocked share, which
 *       raises the next prior. History must exclude prior-driven blocks (or equivalent).</li>
 *   <li><b>Dilution:</b> a share can be diluted by padding with clean traffic - e.g. 10 attacks among 90
 *       clean requests yields 10%, a prior of only 0.03.</li>
 *   <li><b>IP/NAT sharing:</b> unauthenticated clients are keyed by IP ({@link ClientKey}), so every client
 *       behind one NAT or proxy shares a single history.</li>
 * </ul>
 */
@Component
public class ClientHistoryRiskFactor implements RiskFactor {

    public static final String NAME = "client-history";
    public static final double MAX_PRIOR = 0.30;
    public static final long MIN_SAMPLE = 10;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public RiskAdjustment assess(RiskContext context) {
        if (context.inputs().failed(ClientHistory.class)) {
            return RiskAdjustment.missing(NAME, "client history unavailable (provider failed)");
        }
        ClientKey clientKey = ClientKey.of(context.request());
        Optional<ClientHistory> history = context.inputs().get(ClientHistory.class)
                .filter(candidate -> candidate.clientKey().equals(clientKey));
        if (history.isEmpty()) {
            return RiskAdjustment.missing(NAME, "no history for " + clientKey.asString());
        }

        ClientHistory h = history.get();
        if (h.requestsInWindow() < MIN_SAMPLE) {
            return RiskAdjustment.neutral(NAME, "insufficient history: " + h.requestsInWindow()
                    + " request(s), need " + MIN_SAMPLE);
        }
        if (h.blockedInWindow() == 0) {
            return RiskAdjustment.neutral(NAME, "no blocked requests in " + h.requestsInWindow());
        }
        double prior = MAX_PRIOR * ((double) h.blockedInWindow() / h.requestsInWindow());
        return RiskAdjustment.prior(NAME, prior,
                h.blockedInWindow() + " of " + h.requestsInWindow() + " recent requests were blocked");
    }
}
