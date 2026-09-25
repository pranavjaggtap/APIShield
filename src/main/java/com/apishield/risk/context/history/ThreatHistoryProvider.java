package com.apishield.risk.context.history;

import com.apishield.context.RequestContext;
import com.apishield.decision.DefaultDecisionEngine;
import com.apishield.risk.RiskEngineProperties;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputProvider;
import com.apishield.risk.context.inputs.ThreatHistory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

/**
 * Supplies {@link ThreatHistory} - how many of the client's requests in the window
 * {@code [request timestamp - window, request timestamp)} carried detector evidence strong enough to be
 * blocked on its own - from persisted security events via {@link ClientActivityHistory}.
 * <p>
 * A "threat event" is an event whose detector-only {@code threat_score} (the noisy-OR of detector signals,
 * before any context) reached the BLOCK threshold ({@link #MIN_THREAT_SCORE}). Deliberately not the
 * persisted decision: detectors never see contextual priors, so this count cannot be inflated by
 * prior-driven decisions. With neutral context this equals "blocked as threats" (the design's definition).
 * It also excludes weak signals such as a scripted client's User-Agent (0.2), which would otherwise count
 * every automated request as a threat.
 * <p>
 * Scope is per client ({@link ClientKey}), not per path: the ThreatHistory input has no path dimension.
 * <p>
 * Remaining limitations (documented, not corrected here): this count and ClientHistory's blocked count
 * largely describe the same events and are combined by the engine as independent evidence (double
 * counting); a CRITICAL/HIGH route multiplier can still turn sub-threshold evidence into a BLOCK that feeds
 * ClientHistory. Supplying history does not enable priors.
 * <p>
 * Zero threat events yields a zero-count history (NEUTRAL in ThreatHistoryRiskFactor). Errors, timeouts
 * and malformed results propagate so the collector records MISSING/degraded - never blocking the request.
 * Only registered when {@code apishield.risk.history-providers-enabled=true} (default false).
 */
@Component
@ConditionalOnProperty(prefix = "apishield.risk", name = "history-providers-enabled", havingValue = "true")
public class ThreatHistoryProvider implements ContextualInputProvider<ThreatHistory> {

    public static final double MIN_THREAT_SCORE = DefaultDecisionEngine.BLOCK_THRESHOLD;

    private final ClientActivityHistory history;
    private final Duration window;

    @Autowired
    public ThreatHistoryProvider(ClientActivityHistory history, RiskEngineProperties properties) {
        this(history, properties.historyWindow());
    }

    public ThreatHistoryProvider(ClientActivityHistory history, Duration window) {
        this.history = history;
        this.window = window;
    }

    @Override
    public Class<ThreatHistory> type() {
        return ThreatHistory.class;
    }

    @Override
    public Mono<ThreatHistory> provide(RequestContext request) {
        ClientKey clientKey = ClientKey.of(request);
        Instant until = request.timestamp();
        return history.threatEventCount(clientKey, until.minus(window), until, MIN_THREAT_SCORE)
                .map(count -> new ThreatHistory(clientKey, count, window));
    }
}
