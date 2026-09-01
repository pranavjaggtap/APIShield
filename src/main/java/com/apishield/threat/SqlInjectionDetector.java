package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Heuristic SQL injection detector. Inspects the URL path, query parameter names/values,
 * and a small deliberate header allowlist ({@code X-Forwarded-For}, {@code Referer}) for
 * structural patterns commonly seen in SQL injection attempts.
 * <p>
 * This is regex-based heuristic detection, not a SQL parser, and is not a substitute for
 * parameterized queries / prepared statements in any downstream service that talks to a
 * database - it is a defense-in-depth signal at the gateway, not a complete solution.
 * <p>
 * Deliberately does not inspect request bodies: reading a reactive request body requires
 * Spring Cloud Gateway's body-caching mechanism (a body can only be consumed once unless
 * explicitly cached), which is its own design concern left for a future milestone.
 * <p>
 * Patterns require structural context (a keyword combined with an operator, quote, or
 * comment marker) rather than bare substrings, specifically to avoid flagging ordinary
 * English text such as "selection" or "drop shipping".
 */
@Component
public class SqlInjectionDetector implements ThreatDetector {

    private static final String DETECTOR_NAME = "sql-injection";

    private static final double BASE_SEVERITY = 0.9;
    private static final double SEVERITY_STEP_PER_EXTRA_CATEGORY = 0.05;
    private static final double MAX_SEVERITY = 1.0;

    private static final List<String> INSPECTED_HEADERS = List.of("X-Forwarded-For", "Referer");

    private record Rule(String name, Pattern pattern) {
    }

    // Tautology / authentication-bypass: requires the OR/AND ... = ... comparison
    // structure together with a quote character, not just the bare word "or"/"and".
    private static final Rule TAUTOLOGY = new Rule("tautology",
            Pattern.compile("(?i)['\"].{0,5}\\b(or|and)\\b\\s*['\"]?\\s*\\w+\\s*['\"]?\\s*=\\s*['\"]?\\s*\\w+"));

    // UNION SELECT: a highly specific multi-word phrase, essentially never legitimate.
    private static final Rule UNION_SELECT = new Rule("union_select",
            Pattern.compile("(?i)\\bunion\\b(\\s+all)?\\s+select\\b"));

    // SQL comment markers: "--" only when trailing (the classic "comment out the rest of the
    // query" SQLi usage, e.g. "1' OR 1=1 --"), not "--" appearing mid-sentence in normal text
    // such as an em-dash substitute ("see you soon -- take care"); or a /* */ block comment.
    private static final Rule SQL_COMMENT = new Rule("sql_comment",
            Pattern.compile("(--\\s*$)|(/\\*.*?\\*/)"));

    // Stacked query: semicolon followed directly by a destructive DDL/DML keyword.
    private static final Rule STACKED_QUERY = new Rule("stacked_query",
            Pattern.compile("(?i);\\s*(drop|delete|update|insert|alter)\\b"));

    // Time-based blind SQLi: specific function-call syntax.
    private static final Rule TIME_BASED = new Rule("time_based",
            Pattern.compile("(?i)\\bsleep\\s*\\(\\s*\\d+\\s*\\)|\\bwaitfor\\s+delay\\b|\\bbenchmark\\s*\\("));

    private static final List<Rule> RULES = List.of(TAUTOLOGY, UNION_SELECT, SQL_COMMENT, STACKED_QUERY, TIME_BASED);

    @Override
    public Mono<ThreatSignal> detect(SecurityAnalysisContext context) {
        return Mono.fromSupplier(() -> evaluate(context));
    }

    private ThreatSignal evaluate(SecurityAnalysisContext context) {
        List<String> valuesToInspect = collectValues(context);

        List<String> matchedCategories = new ArrayList<>();
        for (Rule rule : RULES) {
            boolean ruleMatched = valuesToInspect.stream().anyMatch(value -> rule.pattern().matcher(value).find());
            if (ruleMatched) {
                matchedCategories.add(rule.name());
            }
        }

        if (matchedCategories.isEmpty()) {
            return new ThreatSignal(DETECTOR_NAME, false, 0.0, "no SQL injection patterns matched");
        }

        double severity = Math.min(MAX_SEVERITY,
                BASE_SEVERITY + SEVERITY_STEP_PER_EXTRA_CATEGORY * (matchedCategories.size() - 1));
        String description = "matched: " + String.join(", ", matchedCategories);
        return new ThreatSignal(DETECTOR_NAME, true, severity, description);
    }

    private List<String> collectValues(SecurityAnalysisContext context) {
        List<String> values = new ArrayList<>();

        addWithDecodedVariant(values, context.path());

        for (Map.Entry<String, List<String>> entry : context.queryParams().entrySet()) {
            addWithDecodedVariant(values, entry.getKey());
            for (String value : entry.getValue()) {
                addWithDecodedVariant(values, value);
            }
        }

        for (String headerName : INSPECTED_HEADERS) {
            List<String> headerValues = context.headers().get(headerName);
            if (headerValues != null) {
                for (String value : headerValues) {
                    addWithDecodedVariant(values, value);
                }
            }
        }

        return values;
    }

    /**
     * Adds the raw value as-is, plus one additional URL-decoding pass as defense against
     * double-encoded payloads (e.g. {@code %2527} decoding once to the literal text
     * {@code %27}, which a second pass turns into {@code '}). Deliberately capped at one
     * extra pass rather than an unbounded decode loop.
     */
    private void addWithDecodedVariant(List<String> values, String raw) {
        if (raw == null) {
            return;
        }
        values.add(raw);
        try {
            String decodedOnceMore = URLDecoder.decode(raw, StandardCharsets.UTF_8);
            if (!decodedOnceMore.equals(raw)) {
                values.add(decodedOnceMore);
            }
        } catch (IllegalArgumentException ignored) {
            // Not decodable as a further percent-encoded value; the raw value is still inspected.
        }
    }
}
