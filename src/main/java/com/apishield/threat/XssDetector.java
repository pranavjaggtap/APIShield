package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.MatchResult;
import java.util.regex.Pattern;

/**
 * Heuristic cross-site scripting (XSS) detector. Inspects the URL path, query parameter
 * names/values, and the same small deliberate header allowlist already used by
 * {@link SqlInjectionDetector} ({@code X-Forwarded-For}, {@code Referer}) for structural
 * patterns commonly seen in reflected/stored/browser-executable XSS payloads.
 * <p>
 * This is regex-based heuristic detection, not an HTML/DOM parser, and cannot catch every
 * possible obfuscation (mutation XSS via browser HTML-parsing quirks, deeply layered mixed
 * encoding, unusual Unicode tricks). It is a defense-in-depth signal at the gateway, not a
 * complete solution - output encoding at render time in any downstream service remains the
 * real defense against XSS.
 * <p>
 * Deliberately does not inspect request bodies, for the same reason as {@link SqlInjectionDetector}:
 * reading a reactive request body requires Spring Cloud Gateway's body-caching mechanism, left
 * for a future milestone.
 * <p>
 * Every pattern requires a structural HTML delimiter ({@code <}, {@code >}, or {@code =}
 * immediately adjacent to a specific keyword) rather than a bare keyword, specifically to avoid
 * flagging ordinary text such as "JavaScript tutorial", "script writing", or "onclick documentation".
 */
@Component
public class XssDetector implements ThreatDetector {

    private static final String DETECTOR_NAME = "xss";

    private static final double BASE_SEVERITY = 0.9;
    private static final double SEVERITY_STEP_PER_EXTRA_CATEGORY = 0.05;
    private static final double MAX_SEVERITY = 1.0;

    private static final List<String> INSPECTED_HEADERS = List.of("X-Forwarded-For", "Referer");

    private record Rule(String name, Pattern pattern) {
    }

    // <script ...> tag: requires the literal "<" delimiter, so "script writing" never matches.
    private static final Rule SCRIPT_TAG = new Rule("script_tag",
            Pattern.compile("(?i)<script\\b[^>]*>"));

    // A specific, deliberately conservative allowlist of common event-handler attribute names,
    // requiring "=" immediately after - not a generic \bon\w+= - so "onclick documentation"
    // (no "=") never matches.
    private static final Rule EVENT_HANDLER = new Rule("event_handler",
            Pattern.compile("(?i)\\b(onerror|onload|onclick|onmouseover|onfocus|onblur|onchange|"
                    + "onsubmit|onkeydown|onkeyup|onmouseout|onmouseenter|onpointerover)\\s*="));

    // javascript: URL scheme: requires the literal ":" right after, so "JavaScript tutorial"
    // (no colon) never matches.
    private static final Rule JAVASCRIPT_URL = new Rule("javascript_url",
            Pattern.compile("(?i)javascript\\s*:"));

    // <iframe>/<object>/<embed>: same structural "<tag" requirement as SCRIPT_TAG.
    private static final Rule DANGEROUS_FRAME_TAG = new Rule("dangerous_frame_tag",
            Pattern.compile("(?i)<(iframe|object|embed)\\b[^>]*>"));

    // <svg ...>: a bare "<svg" essentially never occurs in legitimate REST API path/query
    // values; kept as its own category (rather than folded into DANGEROUS_FRAME_TAG) so the
    // description names it distinctly for future security-event logging.
    private static final Rule SVG_INJECTION = new Rule("svg_injection",
            Pattern.compile("(?i)<svg\\b[^>]*>"));

    // Attribute-breakout: a quote immediately (only whitespace permitted) followed by a tag
    // close/open or an event-handler-looking attribute, e.g. `" onmouseover="..."` or
    // `'><script>`. Tight adjacency means text like "O'Brien>" later in a sentence, where
    // unrelated word characters sit between the quote and the bracket, never matches.
    private static final Rule ATTRIBUTE_BREAKOUT = new Rule("attribute_breakout",
            Pattern.compile("(?i)['\"]\\s*(>|<|on\\w+\\s*=)"));

    private static final List<Rule> RULES = List.of(
            SCRIPT_TAG, EVENT_HANDLER, JAVASCRIPT_URL, DANGEROUS_FRAME_TAG, SVG_INJECTION, ATTRIBUTE_BREAKOUT);

    // Named + numeric HTML entities relevant to reconstructing < > " ' & - deliberately not a
    // full HTML5 entity table (2000+ entries), only enough to unmask angle-bracket/quote
    // obfuscation for this heuristic detector.
    private static final Pattern HTML_ENTITY = Pattern.compile(
            "&lt;|&gt;|&quot;|&apos;|&amp;|&#(\\d+);|&#[xX]([0-9a-fA-F]+);");

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
            return new ThreatSignal(DETECTOR_NAME, false, 0.0, "no XSS patterns matched");
        }

        double severity = Math.min(MAX_SEVERITY,
                BASE_SEVERITY + SEVERITY_STEP_PER_EXTRA_CATEGORY * (matchedCategories.size() - 1));
        String description = "matched: " + String.join(", ", matchedCategories);
        return new ThreatSignal(DETECTOR_NAME, true, severity, description);
    }

    private List<String> collectValues(SecurityAnalysisContext context) {
        List<String> values = new ArrayList<>();

        values.addAll(valueVariants(context.path()));

        for (Map.Entry<String, List<String>> entry : context.queryParams().entrySet()) {
            values.addAll(valueVariants(entry.getKey()));
            for (String value : entry.getValue()) {
                values.addAll(valueVariants(value));
            }
        }

        for (String headerName : INSPECTED_HEADERS) {
            List<String> headerValues = context.headers().get(headerName);
            if (headerValues != null) {
                for (String value : headerValues) {
                    values.addAll(valueVariants(value));
                }
            }
        }

        return values;
    }

    /**
     * Produces up to four variants of a value: the raw value, one extra URL-decode pass,
     * HTML-entity-decoding the raw value, and HTML-entity-decoding the URL-decoded value
     * (to catch encoding layered on top of entities, or entities on top of URL-encoding).
     * Deliberately bounded to one extra pass of each kind, not an unbounded decode loop.
     */
    private List<String> valueVariants(String raw) {
        if (raw == null) {
            return List.of();
        }
        Set<String> variants = new LinkedHashSet<>();
        variants.add(raw);

        String urlDecoded = tryUrlDecode(raw);
        variants.add(urlDecoded);

        variants.add(decodeHtmlEntities(raw));
        variants.add(decodeHtmlEntities(urlDecoded));

        return List.copyOf(variants);
    }

    private String tryUrlDecode(String raw) {
        try {
            return java.net.URLDecoder.decode(raw, java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
            return raw;
        }
    }

    private String decodeHtmlEntities(String value) {
        return HTML_ENTITY.matcher(value).replaceAll(this::decodeEntityMatch);
    }

    private String decodeEntityMatch(MatchResult match) {
        String matched = match.group();
        switch (matched) {
            case "&lt;":
                return "<";
            case "&gt;":
                return ">";
            case "&quot;":
                return "\"";
            case "&apos;":
                return "'";
            case "&amp;":
                return "&";
            default:
                return decodeNumericEntity(match, matched);
        }
    }

    private String decodeNumericEntity(MatchResult match, String matched) {
        try {
            if (match.group(1) != null) {
                return safeCodePointToString(Integer.parseInt(match.group(1)), matched);
            }
            if (match.group(2) != null) {
                return safeCodePointToString(Integer.parseInt(match.group(2), 16), matched);
            }
        } catch (NumberFormatException ignored) {
            // Falls through to returning the original text unchanged.
        }
        return matched;
    }

    /**
     * Only decodes numeric entities within the printable ASCII range, which covers every
     * character this detector actually cares about reconstructing ({@code < > " ' &}).
     * Anything outside that range is left encoded rather than guessed at.
     */
    private String safeCodePointToString(int codePoint, String fallback) {
        if (codePoint < 0x20 || codePoint > 0x7E) {
            return fallback;
        }
        return String.valueOf((char) codePoint);
    }
}
