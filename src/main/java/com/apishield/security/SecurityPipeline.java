package com.apishield.security;

import com.apishield.context.RequestContext;
import com.apishield.decision.DecisionEngine;
import com.apishield.model.Decision;
import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.RiskScoreEngine;
import com.apishield.threat.ThreatDetector;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Orchestrates the security pipeline: runs every registered {@link ThreatDetector} against
 * the detector view ({@link SecurityAnalysisContext}) of the request's {@link RequestContext}, aggregates the resulting signals into a {@link com.apishield.model.RiskScore},
 * and produces a final {@link Decision}. With zero detectors registered, this deterministically
 * yields ALLOW - the gateway is a transparent passthrough until real detectors are added.
 * <p>
 * Fail-closed: if a detector's {@code Mono} errors, that failure is converted into a forced
 * maximum-severity threat signal rather than being silently dropped, so a broken detector
 * cannot cause a request to be allowed unexamined.
 */
@Component
public class SecurityPipeline {

    private final List<ThreatDetector> detectors;
    private final RiskScoreEngine riskScoreEngine;
    private final DecisionEngine decisionEngine;

    public SecurityPipeline(List<ThreatDetector> detectors, RiskScoreEngine riskScoreEngine, DecisionEngine decisionEngine) {
        this.detectors = detectors;
        this.riskScoreEngine = riskScoreEngine;
        this.decisionEngine = decisionEngine;
    }

    public Mono<Decision> evaluate(RequestContext requestContext) {
        SecurityAnalysisContext context = SecurityAnalysisContext.from(requestContext);
        return Flux.fromIterable(detectors)
                .flatMap(detector -> safeDetect(detector, context))
                .collectList()
                .map(riskScoreEngine::score)
                .map(decisionEngine::decide);
    }

    private Mono<ThreatSignal> safeDetect(ThreatDetector detector, SecurityAnalysisContext context) {
        return detector.detect(context)
                .onErrorResume(ex -> Mono.just(new ThreatSignal(
                        detector.getClass().getSimpleName(),
                        true,
                        1.0,
                        "Detector failed - failing closed: " + ex.getMessage())));
    }
}
