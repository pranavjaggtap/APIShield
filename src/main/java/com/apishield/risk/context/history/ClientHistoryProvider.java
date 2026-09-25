package com.apishield.risk.context.history;

import com.apishield.context.RequestContext;
import com.apishield.risk.RiskEngineProperties;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputProvider;
import com.apishield.risk.context.inputs.ClientHistory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

/**
 * Supplies {@link ClientHistory} - how many of the client's requests were evaluated, and how many were
 * BLOCKed, in the window {@code [request timestamp - window, request timestamp)} - from persisted security
 * events via {@link ClientActivityHistory}. The window is anchored to the request's own timestamp (no clock
 * is read), and the current request is never counted.
 * <p>
 * A client with no events yields a zero-count history, which ClientHistoryRiskFactor treats as NEUTRAL
 * (insufficient sample). Errors, timeouts and malformed results propagate so ContextualInputCollector
 * records the input as MISSING and the context as degraded - never blocking the request.
 * <p>
 * "Blocked" means decision BLOCK, the only decision currently enforced; MONITOR, CHALLENGE and THROTTLE
 * requests were not blocked and count only towards the total.
 * <p>
 * Feedback loop: these events are produced by APIShield's own decisions, so once contextual priors are
 * enabled, a request blocked partly because of this prior raises the blocked count that produces the next
 * prior. This provider does not correct for that - it is a documented Phase 4 limitation (see
 * ClientHistoryRiskFactor), and the reason contextual priors remain disabled by default. Supplying history
 * does not enable priors.
 * <p>
 * Only registered when {@code apishield.risk.history-providers-enabled=true} (default false).
 */
@Component
@ConditionalOnProperty(prefix = "apishield.risk", name = "history-providers-enabled", havingValue = "true")
public class ClientHistoryProvider implements ContextualInputProvider<ClientHistory> {

    private final ClientActivityHistory history;
    private final Duration window;

    @Autowired
    public ClientHistoryProvider(ClientActivityHistory history, RiskEngineProperties properties) {
        this(history, properties.historyWindow());
    }

    public ClientHistoryProvider(ClientActivityHistory history, Duration window) {
        this.history = history;
        this.window = window;
    }

    @Override
    public Class<ClientHistory> type() {
        return ClientHistory.class;
    }

    @Override
    public Mono<ClientHistory> provide(RequestContext request) {
        ClientKey clientKey = ClientKey.of(request);
        Instant until = request.timestamp();
        return history.activity(clientKey, until.minus(window), until)
                .map(counts -> new ClientHistory(clientKey, counts.requests(), counts.blocked(), window));
    }
}
