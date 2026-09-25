package com.apishield.security;

import com.apishield.context.RequestContext;
import com.apishield.decision.DecisionEngine;
import com.apishield.event.SecurityEventRecorder;
import com.apishield.model.Decision;
import com.apishield.model.RiskScore;
import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import com.apishield.risk.RiskScoreEngine;
import com.apishield.risk.context.ContextualInputCollector;
import com.apishield.risk.context.RiskContext;
import com.apishield.threat.ThreatDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Orchestrates the security pipeline: runs every registered {@link ThreatDetector} against
 * the detector view ({@link SecurityAnalysisContext}) of the request's {@link RequestContext}, scores the
 * resulting signals with the request's {@link RiskContext} into a {@link RiskScore},
 * and produces a final {@link Decision}. With zero detectors registered, this deterministically
 * yields ALLOW - the gateway is a transparent passthrough until real detectors are added.
 * <p>
 * Fail-closed: if a detector's {@code Mono} errors, that failure is converted into a forced
 * maximum-severity threat signal rather than being silently dropped, so a broken detector
 * cannot cause a request to be allowed unexamined.
 * <p>
 * Contextual inputs are gathered by the {@link ContextualInputCollector} in parallel with the detectors,
 * before scoring; the collector never fails, so an unavailable input only degrades the context.
 * <p>
 * Once the decision is made it is handed to the {@link SecurityEventRecorder}, whose outcome is
 * never awaited and cannot fail this pipeline: the decision returned is always exactly the one the
 * DecisionEngine produced, whatever happens to the recording.
 */
@Component
public class SecurityPipeline {

    private static final Logger log = LoggerFactory.getLogger(SecurityPipeline.class);

    private final List<ThreatDetector> detectors;
    private final RiskScoreEngine riskScoreEngine;
    private final DecisionEngine decisionEngine;
    private final SecurityEventRecorder securityEventRecorder;
    private final ContextualInputCollector contextualInputCollector;

    /** Without contextual input providers - every request is scored with empty contextual inputs. */
    public SecurityPipeline(List<ThreatDetector> detectors, RiskScoreEngine riskScoreEngine,
                            DecisionEngine decisionEngine, SecurityEventRecorder securityEventRecorder) {
        this(detectors, riskScoreEngine, decisionEngine, securityEventRecorder, ContextualInputCollector.none());
    }

    @Autowired
    public SecurityPipeline(List<ThreatDetector> detectors, RiskScoreEngine riskScoreEngine,
                            DecisionEngine decisionEngine, SecurityEventRecorder securityEventRecorder,
                            ContextualInputCollector contextualInputCollector) {
        this.detectors = detectors;
        this.riskScoreEngine = riskScoreEngine;
        this.decisionEngine = decisionEngine;
        this.securityEventRecorder = securityEventRecorder;
        this.contextualInputCollector = contextualInputCollector;
    }

    public Mono<Decision> evaluate(RequestContext requestContext) {
        SecurityAnalysisContext context = SecurityAnalysisContext.from(requestContext);
        Mono<List<ThreatSignal>> signals = Flux.fromIterable(detectors)
                .flatMap(detector -> safeDetect(detector, context))
                .collectList();
        return Mono.zip(signals, contextualInputCollector.collect(requestContext))
                .map(collected -> riskScoreEngine.score(collected.getT1(),
                        new RiskContext(requestContext, collected.getT2())))
                .map(riskScore -> {
                    Decision decision = decisionEngine.decide(riskScore);
                    recordSafely(requestContext, riskScore, decision);
                    return decision;
                });
    }

    private Mono<ThreatSignal> safeDetect(ThreatDetector detector, SecurityAnalysisContext context) {
        return detector.detect(context)
                .onErrorResume(ex -> Mono.just(new ThreatSignal(
                        detector.getClass().getSimpleName(),
                        true,
                        1.0,
                        "Detector failed - failing closed: " + ex.getMessage())));
    }

    /**
     * Guards the decision against any recorder implementation that breaks its no-throw contract.
     */
    private void recordSafely(RequestContext requestContext, RiskScore riskScore, Decision decision) {
        try {
            securityEventRecorder.record(requestContext, riskScore, decision);
        } catch (RuntimeException ex) {
            log.error("Security event recorder failed for request {}; decision {} is unaffected: {}",
                    requestContext.requestId(), decision.outcome(), ex.toString());
        }
    }
}
