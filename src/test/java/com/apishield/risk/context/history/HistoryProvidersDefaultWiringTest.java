package com.apishield.risk.context.history;

import com.apishield.event.PostgresClientActivityHistory;
import com.apishield.risk.RiskEngineProperties;
import com.apishield.risk.context.ContextualInputProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/** Default configuration: history providers are not registered and contextual priors are off. */
@SpringBootTest
class HistoryProvidersDefaultWiringTest {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private RiskEngineProperties properties;

    @Test
    void historyProvidersAreOffByDefault() {
        assertThat(properties.historyProvidersEnabled()).isFalse();
        assertThat(context.getBeansOfType(ClientHistoryProvider.class)).isEmpty();
        assertThat(context.getBeansOfType(ThreatHistoryProvider.class)).isEmpty();
        assertThat(context.getBeansOfType(ContextualInputProvider.class).values())
                .noneMatch(provider -> provider instanceof ClientHistoryProvider || provider instanceof ThreatHistoryProvider);
    }

    @Test
    void contextualPriorsAreOffByDefault() {
        assertThat(properties.contextualPriorsEnabled()).isFalse();
    }

    @Test
    void thePostgresHistoryImplementationIsAvailableButUnused() {
        assertThat(context.getBean(ClientActivityHistory.class)).isInstanceOf(PostgresClientActivityHistory.class);
    }
}
