package com.apishield.event;

import com.apishield.context.RequestContext;
import com.apishield.context.RequestContextFactory;
import com.apishield.context.RouteInfo;
import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import com.apishield.model.ThreatSignal;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurityEventTest {

    private static final Instant TIMESTAMP = Instant.parse("2026-03-01T10:15:30.123456Z");

    private static final ThreatSignal CLEAN = new ThreatSignal("xss", false, 0.0, "no XSS patterns matched");
    private static final ThreatSignal BOT = new ThreatSignal("bot-automation", true, 0.2, "matched: known_automation_tool");
    private static final ThreatSignal SQLI = new ThreatSignal("sql-injection", true, 0.9, "matched: tautology");

    private static RequestContext request(Optional<String> userId) {
        return new RequestContext("req-7", "GET", "/api/users/1", Map.of(), Map.of(), "10.0.0.5", TIMESTAMP,
                Optional.of(new RouteInfo("user-service", URI.create("http://localhost:8081"))), userId);
    }

    @Test
    void allowedRequestProducesAllowEvent() {
        RiskScore riskScore = RiskScore.fromSignalsOnly(0.2, List.of(CLEAN, BOT));
        Decision decision = new Decision(Decision.Outcome.ALLOW, "risk score 0.20 below block threshold 0.50");

        SecurityEvent event = SecurityEvent.create(request(Optional.of("user-42")), riskScore, decision);

        assertThat(event.id()).isNull();
        assertThat(event.requestId()).isEqualTo("req-7");
        assertThat(event.occurredAt()).isEqualTo(TIMESTAMP);
        assertThat(event.method()).isEqualTo("GET");
        assertThat(event.path()).isEqualTo("/api/users/1");
        assertThat(event.clientIp()).isEqualTo("10.0.0.5");
        assertThat(event.routeId()).isEqualTo("user-service");
        assertThat(event.decision()).isEqualTo("ALLOW");
        assertThat(event.decisionReason()).isEqualTo("risk score 0.20 below block threshold 0.50");
        assertThat(event.riskScore()).isEqualTo(0.2);
        assertThat(event.threatScore()).isEqualTo(0.2);
    }

    @Test
    void blockedRequestProducesBlockEventWithScoresAndSignals() {
        RiskScore riskScore = RiskScore.fromSignalsOnly(0.92, List.of(CLEAN, BOT, SQLI));
        Decision decision = new Decision(Decision.Outcome.BLOCK, "risk score 0.92 met or exceeded block threshold 0.50");

        SecurityEvent event = SecurityEvent.create(request(Optional.of("user-42")), riskScore, decision);

        assertThat(event.decision()).isEqualTo("BLOCK");
        assertThat(event.riskScore()).isEqualTo(0.92);
        assertThat(event.threatScore()).isEqualTo(0.92);
        assertThat(event.signalDetectors()).containsExactly("xss", "bot-automation", "sql-injection");
        assertThat(event.signalDetected()).containsExactly(false, true, true);
        assertThat(event.signalSeverities()).containsExactly(0.0, 0.2, 0.9);
        assertThat(event.signalDescriptions())
                .containsExactly("no XSS patterns matched", "matched: known_automation_tool", "matched: tautology");
        assertThat(event.threatSignals()).containsExactly(CLEAN, BOT, SQLI);
    }

    @Test
    void authenticatedUserIdIsCaptured() {
        SecurityEvent event = SecurityEvent.create(request(Optional.of("user-42")),
                RiskScore.fromSignalsOnly(0.0, List.of()), new Decision(Decision.Outcome.ALLOW, "ok"));

        assertThat(event.userId()).isEqualTo("user-42");
    }

    @Test
    void unauthenticatedRequestHasNullUserIdAndRoute() {
        RequestContext anonymousUnrouted = new RequestContext("req-8", "GET", "/unrouted", Map.of(), Map.of(),
                "10.0.0.5", TIMESTAMP, Optional.empty(), Optional.empty());

        SecurityEvent event = SecurityEvent.create(anonymousUnrouted,
                RiskScore.fromSignalsOnly(0.0, List.of()), new Decision(Decision.Outcome.ALLOW, "ok"));

        assertThat(event.userId()).isNull();
        assertThat(event.routeId()).isNull();
        assertThat(event.signalDetectors()).isEmpty();
    }

    @Test
    void credentialsAreNeverPersisted() {
        String jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTQyIn0.c2lnbmF0dXJl";
        String cookie = "SESSION=super-secret-session";
        String basic = "Basic dXNlcjpzM2NyM3Q=";
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/users/1")
                .header("Authorization", "Bearer " + jwt)
                .header("Proxy-Authorization", basic)
                .header("Cookie", cookie)
                .header("User-Agent", "curl/8.0")
                .remoteAddress(new InetSocketAddress("10.0.0.5", 5000))
                .build());
        RequestContext request = new RequestContextFactory().create(exchange).withUserId("user-42");

        SecurityEvent event = SecurityEvent.create(request, RiskScore.fromSignalsOnly(0.2, List.of(BOT)),
                new Decision(Decision.Outcome.ALLOW, "ok"));

        assertThat(event.toString())
                .doesNotContain(jwt)
                .doesNotContain("super-secret-session")
                .doesNotContain("dXNlcjpzM2NyM3Q=")
                .doesNotContainIgnoringCase("authorization")
                .doesNotContainIgnoringCase("cookie");
    }

    @Test
    void everyFiveTierOutcomeIsStoredByNameInTheExistingDecisionColumn() {
        for (Decision.Outcome outcome : Decision.Outcome.values()) {
            SecurityEvent event = SecurityEvent.create(request(Optional.of("user-42")),
                    RiskScore.fromSignalsOnly(0.5, List.of(BOT)), new Decision(outcome, "reason for " + outcome));

            assertThat(event.decision()).isEqualTo(outcome.name());
            assertThat(event.decisionReason()).isEqualTo("reason for " + outcome);
        }
    }

    @Test
    void signalArraysMustStayAligned() {
        assertThatThrownBy(() -> new SecurityEvent(null, "req-1", TIMESTAMP, "GET", "/", "10.0.0.5", null, null,
                "ALLOW", "ok", 0.0, 0.0, List.of("a", "b"), List.of(true), List.of(0.1, 0.2), List.of("x", "y")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
