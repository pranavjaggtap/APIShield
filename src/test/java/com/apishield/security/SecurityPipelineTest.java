package com.apishield.security;

import com.apishield.decision.DecisionEngine;
import com.apishield.decision.DefaultDecisionEngine;
import com.apishield.model.Decision;
import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.DefaultRiskScoreEngine;
import com.apishield.risk.RiskScoreEngine;
import com.apishield.threat.ThreatDetector;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityPipelineTest {

    private final RiskScoreEngine riskScoreEngine = new DefaultRiskScoreEngine();
    private final DecisionEngine decisionEngine = new DefaultDecisionEngine();

    private final SecurityAnalysisContext context = new SecurityAnalysisContext(
            "req-1", "GET", "/api/users/1", Map.of(), "127.0.0.1", Instant.now());

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
}
