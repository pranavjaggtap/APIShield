package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Heuristic bot/automation detector based purely on the shape of a single request's headers -
 * no request history, no Redis, no external services. Deliberately does not duplicate
 * {@link FrequencyAbuseDetector}'s responsibility: that detector answers "is this client
 * making too many requests over time"; this one answers "does this one request look like it
 * came from unconfigured automated tooling rather than a browser."
 * <p>
 * {@code X-Forwarded-For} is never consulted - this detector has no client-identity concept
 * at all, only per-request header shape, so there is nothing to spoof via that header here.
 * <p>
 * Severity is deliberately calibrated low per signal: a plain {@code curl} request (this
 * project's own established end-to-end testing pattern) scores only 0.2 and stays well under
 * the existing 0.5 block threshold, since legitimate system-to-system clients (scripts,
 * monitoring probes, integration tests) routinely look like "automation" by these signals
 * without being malicious. Only when multiple independent weak signals converge - e.g. no
 * User-Agent at all combined with none of the usual browser Accept* headers - does the
 * combined severity cross the threshold.
 * <p>
 * This is explicitly not a strong standalone signal: User-Agent and header presence are fully
 * client-controlled and trivially spoofed by a motivated attacker who simply mimics a real
 * browser. It catches naive/default-configured automation, not a determined adversary.
 */
@Component
public class BotAutomationDetector implements ThreatDetector {

    private static final String DETECTOR_NAME = "bot-automation";

    private static final double MISSING_USER_AGENT_WEIGHT = 0.3;
    private static final double KNOWN_AUTOMATION_TOOL_WEIGHT = 0.2;
    private static final double MISSING_BROWSER_HEADERS_WEIGHT = 0.2;
    private static final double MAX_SEVERITY = 1.0;

    private static final String USER_AGENT_HEADER = "User-Agent";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String ACCEPT_LANGUAGE_HEADER = "Accept-Language";
    private static final String ACCEPT_ENCODING_HEADER = "Accept-Encoding";

    // Well-documented default User-Agent substrings set automatically by non-browser HTTP
    // clients/tools. Real browser UAs (Mozilla/5.0 ... AppleWebKit ... Chrome/...) never
    // structurally contain these, so this is deterministic substring matching, not a guess.
    private static final List<String> AUTOMATION_TOOL_SIGNATURES = List.of(
            "curl/",
            "python-requests/",
            "python-urllib",
            "go-http-client",
            "okhttp",
            "postmanruntime",
            "insomnia",
            "libwww-perl",
            "wget/",
            "scrapy",
            "node-fetch",
            "axios/",
            "java-http-client",
            "java/",
            "bot",
            "crawler",
            "spider"
    );

    @Override
    public Mono<ThreatSignal> detect(SecurityAnalysisContext context) {
        return Mono.fromSupplier(() -> evaluate(context));
    }

    private ThreatSignal evaluate(SecurityAnalysisContext context) {
        List<String> matchedCategories = new ArrayList<>();
        double severity = 0.0;

        String userAgent = firstHeaderValue(context, USER_AGENT_HEADER);

        if (isBlank(userAgent)) {
            matchedCategories.add("missing_user_agent");
            severity += MISSING_USER_AGENT_WEIGHT;
        } else if (matchesKnownAutomationTool(userAgent)) {
            matchedCategories.add("known_automation_tool");
            severity += KNOWN_AUTOMATION_TOOL_WEIGHT;
        }

        if (isBlank(firstHeaderValue(context, ACCEPT_HEADER))
                && isBlank(firstHeaderValue(context, ACCEPT_LANGUAGE_HEADER))
                && isBlank(firstHeaderValue(context, ACCEPT_ENCODING_HEADER))) {
            matchedCategories.add("missing_browser_headers");
            severity += MISSING_BROWSER_HEADERS_WEIGHT;
        }

        if (matchedCategories.isEmpty()) {
            return new ThreatSignal(DETECTOR_NAME, false, 0.0, "no bot/automation signals matched");
        }

        String description = "matched: " + String.join(", ", matchedCategories);
        return new ThreatSignal(DETECTOR_NAME, true, Math.min(MAX_SEVERITY, severity), description);
    }

    private boolean matchesKnownAutomationTool(String userAgent) {
        String lowerCaseUserAgent = userAgent.toLowerCase(Locale.ROOT);
        return AUTOMATION_TOOL_SIGNATURES.stream().anyMatch(lowerCaseUserAgent::contains);
    }

    private String firstHeaderValue(SecurityAnalysisContext context, String headerName) {
        List<String> values = context.headers().get(headerName);
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.get(0);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
