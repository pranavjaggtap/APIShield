package com.apishield.security;

import com.apishield.context.RequestContext;
import com.apishield.context.RequestContextFactory;
import com.apishield.decision.DecisionEngine;
import com.apishield.decision.DefaultDecisionEngine;
import com.apishield.event.AsyncSecurityEventRecorder;
import com.apishield.event.SecurityEventRecorder;
import com.apishield.event.SecurityEventRepository;
import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.ContextualRiskScoreEngine;
import com.apishield.risk.RiskScoreEngine;
import com.apishield.risk.RiskTestContexts;
import com.apishield.risk.context.ContextualInputCollector;
import com.apishield.risk.context.ContextualInputProvider;
import com.apishield.risk.context.RiskContext;
import com.apishield.risk.context.inputs.RouteProfile;
import com.apishield.risk.factor.IdentityRiskFactor;
import com.apishield.risk.factor.RouteSensitivityRiskFactor;
import com.apishield.threat.BotAutomationDetector;
import com.apishield.threat.SqlInjectionDetector;
import com.apishield.threat.ThreatDetector;
import com.apishield.threat.XssDetector;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityPipelineTest {

    private final RiskScoreEngine riskScoreEngine = new ContextualRiskScoreEngine();
    private final DecisionEngine decisionEngine = new DefaultDecisionEngine();

    private record Recorded(RequestContext request, RiskScore riskScore, Decision decision) {
    }

    private final List<Recorded> recorded = new CopyOnWriteArrayList<>();
    private final SecurityEventRecorder recorder =
            (request, riskScore, decision) -> recorded.add(new Recorded(request, riskScore, decision));

    private final RequestContext context = new RequestContext(
            "req-1", "GET", "/api/users/1", Map.of(), Map.of(), "127.0.0.1", Instant.now(),
            Optional.empty(), Optional.empty());

    private static RequestContext contextFrom(MockServerHttpRequest request) {
        return new RequestContextFactory().create(MockServerWebExchange.from(request));
    }

    private SecurityPipeline pipelineWithRealStatelessDetectors() {
        return new SecurityPipeline(
                List.of(new SqlInjectionDetector(), new XssDetector(), new BotAutomationDetector()),
                riskScoreEngine, decisionEngine, recorder);
    }

    @Test
    void zeroDetectorsResultInAllow() {
        SecurityPipeline pipeline = new SecurityPipeline(List.of(), riskScoreEngine, decisionEngine, recorder);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();
    }

    @Test
    void combinesMultipleDetectorSignalsIntoDecision() {
        ThreatDetector clean = ctx -> Mono.just(new ThreatSignal("clean-detector", false, 0.0, "ok"));
        ThreatDetector highThreat = ctx -> Mono.just(new ThreatSignal("threat-detector", true, 0.9, "bad"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(clean, highThreat), riskScoreEngine, decisionEngine, recorder);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    @Test
    void lowSeverityThreatsRemainBelowThresholdAndAllow() {
        ThreatDetector minor = ctx -> Mono.just(new ThreatSignal("minor-detector", true, 0.1, "low risk"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(minor), riskScoreEngine, decisionEngine, recorder);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();
    }

    @Test
    void detectorFailureFailsClosed() {
        ThreatDetector failing = ctx -> Mono.error(new RuntimeException("boom"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(failing), riskScoreEngine, decisionEngine, recorder);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    @Test
    void oneFailingDetectorFailsClosedEvenIfOthersAreClean() {
        ThreatDetector clean = ctx -> Mono.just(new ThreatSignal("clean-detector", false, 0.0, "ok"));
        ThreatDetector failing = ctx -> Mono.error(new RuntimeException("boom"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(clean, failing), riskScoreEngine, decisionEngine, recorder);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    // --- RequestContext compatibility ----------------------------------------------------

    @Test
    void detectorsReceiveAnalysisContextDerivedFromRequestContext() {
        RequestContext requestContext = contextFrom(MockServerHttpRequest.get("/api/users/1")
                .queryParam("q", "hello")
                .header("User-Agent", "curl/8.0")
                .remoteAddress(new InetSocketAddress("10.0.0.5", 54321))
                .build());
        AtomicReference<SecurityAnalysisContext> received = new AtomicReference<>();
        ThreatDetector recording = ctx -> {
            received.set(ctx);
            return Mono.just(new ThreatSignal("recording", false, 0.0, "ok"));
        };
        SecurityPipeline pipeline = new SecurityPipeline(List.of(recording), riskScoreEngine, decisionEngine, recorder);

        StepVerifier.create(pipeline.evaluate(requestContext))
                .expectNextCount(1)
                .verifyComplete();

        SecurityAnalysisContext analysisContext = received.get();
        assertThat(analysisContext.requestId()).isEqualTo(requestContext.requestId());
        assertThat(analysisContext.method()).isEqualTo("GET");
        assertThat(analysisContext.path()).isEqualTo("/api/users/1");
        assertThat(analysisContext.headers()).isSameAs(requestContext.headers());
        assertThat(analysisContext.queryParams()).isSameAs(requestContext.queryParams());
        assertThat(analysisContext.clientIp()).isEqualTo("10.0.0.5");
        assertThat(analysisContext.timestamp()).isEqualTo(requestContext.timestamp());
    }

    @Test
    void riskEngineReceivesRiskContextForTheRequest() {
        AtomicReference<RiskContext> received = new AtomicReference<>();
        RiskScoreEngine recordingEngine = (signals, riskContext) -> {
            received.set(riskContext);
            return riskScoreEngine.score(signals, riskContext);
        };
        SecurityPipeline pipeline = new SecurityPipeline(List.of(), recordingEngine, decisionEngine, recorder);

        StepVerifier.create(pipeline.evaluate(context))
                .expectNextCount(1)
                .verifyComplete();

        assertThat(received.get().request()).isSameAs(context);
        assertThat(received.get().inputs().isEmpty()).isTrue();
    }

    @Test
    void realDetectorsAllowBrowserLikeRequest() {
        RequestContext requestContext = contextFrom(MockServerHttpRequest.get("/api/users/1")
                .header("User-Agent", "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
                .header("Accept", "application/json")
                .build());

        StepVerifier.create(pipelineWithRealStatelessDetectors().evaluate(requestContext))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();
    }

    @Test
    void realDetectorsStillBlockSqlInjectionInQuery() {
        RequestContext requestContext = contextFrom(MockServerHttpRequest.get("/api/users?id=1%27%20OR%20%271%27%3D%271")
                .header("User-Agent", "Mozilla/5.0 Chrome/120.0")
                .header("Accept", "application/json")
                .build());

        StepVerifier.create(pipelineWithRealStatelessDetectors().evaluate(requestContext))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    @Test
    void realDetectorsStillBlockXssInQuery() {
        RequestContext requestContext = contextFrom(MockServerHttpRequest.get("/api/users?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
                .header("User-Agent", "Mozilla/5.0 Chrome/120.0")
                .header("Accept", "application/json")
                .build());

        StepVerifier.create(pipelineWithRealStatelessDetectors().evaluate(requestContext))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    @Test
    void lowerCaseHeadersStillReachBotDetectorLikeBefore() {
        // A plain curl-style request (UA present, Accept present) scores 0.2 and is allowed; if
        // lower-cased header names were lost, the bot detector would instead see a missing
        // User-Agent AND missing Accept* headers (0.5) and block.
        RequestContext requestContext = contextFrom(MockServerHttpRequest.get("/api/users/1")
                .header("user-agent", "curl/8.0")
                .header("accept", "*/*")
                .build());

        StepVerifier.create(pipelineWithRealStatelessDetectors().evaluate(requestContext))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();
    }

    @Test
    void authenticatedIdentityDoesNotChangeDetectorDecisions() {
        RequestContext cleanRequest = contextFrom(MockServerHttpRequest.get("/api/users/1")
                .header("User-Agent", "Mozilla/5.0 Chrome/120.0")
                .header("Accept", "application/json")
                .build());
        RequestContext sqlInjection = contextFrom(MockServerHttpRequest.get("/api/users?id=1%27%20OR%20%271%27%3D%271")
                .header("User-Agent", "Mozilla/5.0 Chrome/120.0")
                .header("Accept", "application/json")
                .build());
        SecurityPipeline pipeline = pipelineWithRealStatelessDetectors();

        StepVerifier.create(pipeline.evaluate(cleanRequest.withUserId("user-42")))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();
        StepVerifier.create(pipeline.evaluate(sqlInjection.withUserId("user-42")))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    @Test
    void requestWithNoUserAgentAndNoAcceptHeadersIsChallengedByBotDetector() {
        // Bot detector severity 0.5 (missing User-Agent + missing browser headers). BLOCK under the former
        // single 0.50 threshold; CHALLENGE ([0.50, 0.65)) under the five-tier model.
        RequestContext requestContext = contextFrom(MockServerHttpRequest.get("/api/users/1").build());

        StepVerifier.create(pipelineWithRealStatelessDetectors().evaluate(requestContext))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.CHALLENGE))
                .verifyComplete();
    }

    // --- security event recording ------------------------------------------------------------

    @Test
    void allowedDecisionIsRecordedWithItsContextAndRiskScore() {
        RequestContext authenticated = context.withUserId("user-42");
        ThreatDetector minor = ctx -> Mono.just(new ThreatSignal("minor-detector", true, 0.2, "low risk"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(minor), riskScoreEngine, decisionEngine, recorder);

        StepVerifier.create(pipeline.evaluate(authenticated))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();

        assertThat(recorded).hasSize(1);
        Recorded event = recorded.get(0);
        assertThat(event.request()).isSameAs(authenticated);
        assertThat(event.decision().outcome()).isEqualTo(Decision.Outcome.ALLOW);
        assertThat(event.riskScore().value()).isEqualTo(0.2);
        assertThat(event.riskScore().contributingSignals()).extracting(ThreatSignal::detectorName)
                .containsExactly("minor-detector");
    }

    @Test
    void blockedDecisionIsRecordedExactlyAsReturned() {
        ThreatDetector clean = ctx -> Mono.just(new ThreatSignal("clean-detector", false, 0.0, "ok"));
        ThreatDetector high = ctx -> Mono.just(new ThreatSignal("threat-detector", true, 0.9, "bad"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(clean, high), riskScoreEngine, decisionEngine, recorder);
        AtomicReference<Decision> returned = new AtomicReference<>();

        StepVerifier.create(pipeline.evaluate(context))
                .consumeNextWith(returned::set)
                .verifyComplete();

        assertThat(returned.get().outcome()).isEqualTo(Decision.Outcome.BLOCK);
        assertThat(recorded).hasSize(1);
        assertThat(recorded.get(0).decision()).isEqualTo(returned.get());
        assertThat(recorded.get(0).riskScore().value()).isEqualTo(0.9);
        assertThat(recorded.get(0).riskScore().contributingSignals()).hasSize(2);
    }

    @Test
    void throwingRecorderDoesNotChangeBlockDecision() {
        SecurityEventRecorder throwing = (request, riskScore, decision) -> {
            throw new IllegalStateException("database down");
        };
        ThreatDetector high = ctx -> Mono.just(new ThreatSignal("threat-detector", true, 0.9, "bad"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(high), riskScoreEngine, decisionEngine, throwing);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    @Test
    void throwingRecorderDoesNotChangeAllowDecision() {
        SecurityEventRecorder throwing = (request, riskScore, decision) -> {
            throw new IllegalStateException("database down");
        };
        SecurityPipeline pipeline = new SecurityPipeline(List.of(), riskScoreEngine, decisionEngine, throwing);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();
    }

    @Test
    void failingDatabaseSaveDoesNotChangeBlockDecision() {
        SecurityEventRepository repository = mock(SecurityEventRepository.class);
        when(repository.save(any())).thenReturn(Mono.error(new RuntimeException("connection refused")));
        ThreatDetector high = ctx -> Mono.just(new ThreatSignal("threat-detector", true, 0.9, "bad"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(high), riskScoreEngine, decisionEngine,
                new AsyncSecurityEventRecorder(repository));

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    @Test
    void failingDatabaseSaveDoesNotChangeAllowDecision() {
        SecurityEventRepository repository = mock(SecurityEventRepository.class);
        when(repository.save(any())).thenReturn(Mono.error(new RuntimeException("connection refused")));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(), riskScoreEngine, decisionEngine,
                new AsyncSecurityEventRecorder(repository));

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();
    }

    @Test
    void hangingDatabaseDoesNotDelayTheDecision() {
        SecurityEventRepository repository = mock(SecurityEventRepository.class);
        when(repository.save(any())).thenReturn(Mono.never());
        ThreatDetector high = ctx -> Mono.just(new ThreatSignal("threat-detector", true, 0.9, "bad"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(high), riskScoreEngine, decisionEngine,
                new AsyncSecurityEventRecorder(repository, Duration.ofMinutes(5), 10));

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .expectComplete()
                .verify(Duration.ofSeconds(2));
    }

    // --- contextual inputs (Phase 2) ------------------------------------------------------------

    private static final RequestContext ALICE_ON_USER_SERVICE = RiskTestContexts.authenticated("alice");

    private static ContextualInputProvider<RouteProfile> routeProvider(Mono<RouteProfile> result) {
        return new ContextualInputProvider<>() {
            @Override
            public Class<RouteProfile> type() {
                return RouteProfile.class;
            }

            @Override
            public Mono<RouteProfile> provide(RequestContext request) {
                return result;
            }
        };
    }

    private SecurityPipeline contextualPipeline(double severity, ContextualInputCollector collector) {
        ThreatDetector detector = ctx -> Mono.just(new ThreatSignal("bot-automation", true, severity, "matched"));
        RiskScoreEngine contextualEngine = new ContextualRiskScoreEngine(
                List.of(new RouteSensitivityRiskFactor(), new IdentityRiskFactor()), false);
        return new SecurityPipeline(List.of(detector), contextualEngine, decisionEngine, recorder, collector);
    }

    @Test
    void contextualInputsReachTheEngineAndCanChangeTheScore() {
        ContextualInputCollector highRoute = new ContextualInputCollector(List.of(routeProvider(
                Mono.just(new RouteProfile(RiskTestContexts.ROUTE_ID, RouteProfile.Sensitivity.HIGH)))), Duration.ofSeconds(1));

        // 0.4 on a HIGH route scores 0.535 (CHALLENGE); without context it stays 0.4 (MONITOR).
        StepVerifier.create(contextualPipeline(0.4, highRoute).evaluate(ALICE_ON_USER_SERVICE))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.CHALLENGE))
                .verifyComplete();
        StepVerifier.create(contextualPipeline(0.4, ContextualInputCollector.none()).evaluate(ALICE_ON_USER_SERVICE))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.MONITOR))
                .verifyComplete();

        assertThat(recorded.get(0).riskScore().contextMultiplier()).isEqualTo(1.5);
        assertThat(recorded.get(1).riskScore().value()).isEqualTo(0.4);
    }

    @Test
    void failingProviderDegradesContextButNeitherBlocksNorChangesTheDecision() {
        ContextualInputCollector failing = new ContextualInputCollector(
                List.of(routeProvider(Mono.error(new IllegalStateException("config store down")))), Duration.ofSeconds(1));

        StepVerifier.create(contextualPipeline(0.4, failing).evaluate(ALICE_ON_USER_SERVICE))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.MONITOR))
                .verifyComplete();
        StepVerifier.create(contextualPipeline(0.9, failing).evaluate(ALICE_ON_USER_SERVICE))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();

        assertThat(recorded).allSatisfy(event -> assertThat(event.riskScore().degraded()).isTrue());
        assertThat(recorded.get(0).riskScore().value()).isEqualTo(0.4);
        assertThat(recorded.get(1).riskScore().value()).isEqualTo(0.9);
    }

    @Test
    void hangingProviderTimesOutWithoutBlockingTheRequest() {
        ContextualInputCollector hanging = new ContextualInputCollector(
                List.of(routeProvider(Mono.never())), Duration.ofMillis(50));

        StepVerifier.create(contextualPipeline(0.9, hanging).evaluate(ALICE_ON_USER_SERVICE))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .expectComplete()
                .verify(Duration.ofSeconds(2));

        assertThat(recorded.get(0).riskScore().degraded()).isTrue();
    }

    // --- five-tier decisions (Phase 3) -----------------------------------------------------------

    @Test
    void eachTierIsProducedAndRecordedWithItsUnchangedRiskScore() {
        double[] severities = {0.1, 0.3, 0.55, 0.7, 0.9};
        Decision.Outcome[] expected = {Decision.Outcome.ALLOW, Decision.Outcome.MONITOR, Decision.Outcome.CHALLENGE,
                Decision.Outcome.THROTTLE, Decision.Outcome.BLOCK};

        for (int i = 0; i < severities.length; i++) {
            double severity = severities[i];
            ThreatDetector detector = ctx -> Mono.just(new ThreatSignal("detector", true, severity, "matched"));
            SecurityPipeline pipeline = new SecurityPipeline(List.of(detector), riskScoreEngine, decisionEngine, recorder);
            Decision.Outcome outcome = expected[i];

            StepVerifier.create(pipeline.evaluate(context))
                    .assertNext(decision -> assertThat(decision.outcome()).as("severity %s", severity).isEqualTo(outcome))
                    .verifyComplete();
        }

        assertThat(recorded).extracting(event -> event.decision().outcome()).containsExactly(expected);
        assertThat(recorded).extracting(event -> event.riskScore().value())
                .containsExactly(0.1, 0.3, 0.55, 0.7, 0.9);
    }
}
