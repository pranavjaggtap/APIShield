package com.apishield.security;

import com.apishield.context.RequestContext;
import com.apishield.context.RequestContextFactory;
import com.apishield.decision.DecisionEngine;
import com.apishield.decision.DefaultDecisionEngine;
import com.apishield.model.Decision;
import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.DefaultRiskScoreEngine;
import com.apishield.risk.RiskScoreEngine;
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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityPipelineTest {

    private final RiskScoreEngine riskScoreEngine = new DefaultRiskScoreEngine();
    private final DecisionEngine decisionEngine = new DefaultDecisionEngine();

    private final RequestContext context = new RequestContext(
            "req-1", "GET", "/api/users/1", Map.of(), Map.of(), "127.0.0.1", Instant.now(),
            Optional.empty(), Optional.empty());

    private static RequestContext contextFrom(MockServerHttpRequest request) {
        return new RequestContextFactory().create(MockServerWebExchange.from(request));
    }

    private SecurityPipeline pipelineWithRealStatelessDetectors() {
        return new SecurityPipeline(
                List.of(new SqlInjectionDetector(), new XssDetector(), new BotAutomationDetector()),
                riskScoreEngine, decisionEngine);
    }

    @Test
    void zeroDetectorsResultInAllow() {
        SecurityPipeline pipeline = new SecurityPipeline(List.of(), riskScoreEngine, decisionEngine);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();
    }

    @Test
    void combinesMultipleDetectorSignalsIntoDecision() {
        ThreatDetector clean = ctx -> Mono.just(new ThreatSignal("clean-detector", false, 0.0, "ok"));
        ThreatDetector highThreat = ctx -> Mono.just(new ThreatSignal("threat-detector", true, 0.9, "bad"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(clean, highThreat), riskScoreEngine, decisionEngine);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    @Test
    void lowSeverityThreatsRemainBelowThresholdAndAllow() {
        ThreatDetector minor = ctx -> Mono.just(new ThreatSignal("minor-detector", true, 0.1, "low risk"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(minor), riskScoreEngine, decisionEngine);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.ALLOW))
                .verifyComplete();
    }

    @Test
    void detectorFailureFailsClosed() {
        ThreatDetector failing = ctx -> Mono.error(new RuntimeException("boom"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(failing), riskScoreEngine, decisionEngine);

        StepVerifier.create(pipeline.evaluate(context))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }

    @Test
    void oneFailingDetectorFailsClosedEvenIfOthersAreClean() {
        ThreatDetector clean = ctx -> Mono.just(new ThreatSignal("clean-detector", false, 0.0, "ok"));
        ThreatDetector failing = ctx -> Mono.error(new RuntimeException("boom"));
        SecurityPipeline pipeline = new SecurityPipeline(List.of(clean, failing), riskScoreEngine, decisionEngine);

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
        SecurityPipeline pipeline = new SecurityPipeline(List.of(recording), riskScoreEngine, decisionEngine);

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
    void requestWithNoUserAgentAndNoAcceptHeadersIsStillBlockedByBotDetector() {
        RequestContext requestContext = contextFrom(MockServerHttpRequest.get("/api/users/1").build());

        StepVerifier.create(pipelineWithRealStatelessDetectors().evaluate(requestContext))
                .assertNext(decision -> assertThat(decision.outcome()).isEqualTo(Decision.Outcome.BLOCK))
                .verifyComplete();
    }
}
