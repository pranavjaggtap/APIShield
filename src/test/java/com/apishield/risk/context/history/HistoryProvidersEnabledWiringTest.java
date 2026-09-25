package com.apishield.risk.context.history;

import com.apishield.model.RiskAdjustment;
import com.apishield.model.RiskAdjustment.Availability;
import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.ContextualRiskScoreEngine;
import com.apishield.risk.RiskEngineProperties;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.ClientKey;
import com.apishield.risk.context.ContextualInputCollector;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.RiskContext;
import com.apishield.risk.context.inputs.ClientHistory;
import com.apishield.risk.context.inputs.ThreatHistory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Enabling the history providers must NOT enable contextual priors: the production-wired engine records
 * the priors the history would propose but applies none, so no score changes.
 */
@SpringBootTest(properties = {
        "apishield.risk.history-providers-enabled=true",
        "apishield.risk.history-window=30m"
})
class HistoryProvidersEnabledWiringTest {

    private static final ClientKey ALICE = new ClientKey(ClientKey.Kind.USER, "alice");

    @Autowired
    private ApplicationContext context;

    @Autowired
    private RiskEngineProperties properties;

    @Autowired
    private ContextualRiskScoreEngine engine;

    @Autowired
    private ContextualInputCollector collector;

    @Test
    void providersAreRegisteredWithTheCollectorWhenEnabled() {
        ClientHistoryProvider clientHistory = context.getBean(ClientHistoryProvider.class);
        ThreatHistoryProvider threatHistory = context.getBean(ThreatHistoryProvider.class);

        @SuppressWarnings("unchecked")
        List<Object> registered = (List<Object>) ReflectionTestUtils.getField(collector, "providers");
        assertThat(registered).contains(clientHistory, threatHistory);
        assertThat(properties.historyWindow()).isEqualTo(Duration.ofMinutes(30));
    }

    @Test
    void enablingProvidersDoesNotEnableContextualPriors() {
        assertThat(properties.contextualPriorsEnabled()).isFalse();

        // The heaviest history the providers could return, for a request carrying no threat at all.
        ContextualInputs heavyHistory = ContextualInputs.builder()
                .put(ClientHistory.class, new ClientHistory(ALICE, 100, 100, Duration.ofMinutes(30)))
                .put(ThreatHistory.class, new ThreatHistory(ALICE, 100, Duration.ofMinutes(30)))
                .build();
        RiskScore clean = engine.score(List.of(), new RiskContext(RiskTestContexts.authenticated("alice"), heavyHistory));
        RiskScore weak = engine.score(List.of(new ThreatSignal("bot-automation", true, 0.2, "curl")),
                new RiskContext(RiskTestContexts.authenticated("alice"), heavyHistory));

        assertThat(clean.value()).isEqualTo(0.0);
        assertThat(weak.value()).isEqualTo(0.2);
        assertThat(clean.contextualPrior()).isEqualTo(0.0);
        assertThat(clean.adjustments())
                .filteredOn(adjustment -> adjustment.factor().endsWith("history"))
                .hasSize(2)
                .allSatisfy(adjustment -> {
                    assertThat(adjustment.prior()).isEqualTo(0.0);
                    assertThat(adjustment.availability()).isEqualTo(Availability.NEUTRAL);
                    assertThat(adjustment.reason()).contains("not applied: contextual priors disabled");
                });
        assertThat(clean.adjustments()).extracting(RiskAdjustment::factor).contains("client-history", "threat-history");
    }
}
