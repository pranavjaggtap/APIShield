package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class XssDetectorTest {

    private final XssDetector detector = new XssDetector();

    // --- helpers -----------------------------------------------------------------------

    private static SecurityAnalysisContext context(String path, Map<String, List<String>> queryParams) {
        return new SecurityAnalysisContext(
                "req-1", "GET", path, Map.of(), queryParams, "127.0.0.1", Instant.now());
    }

    private static SecurityAnalysisContext contextWithHeader(String headerName, String headerValue) {
        return new SecurityAnalysisContext(
                "req-1", "GET", "/api/users/1", Map.of(headerName, List.of(headerValue)),
                Map.of(), "127.0.0.1", Instant.now());
    }

    private static Map<String, List<String>> queryParam(String name, String value) {
        return Map.of(name, List.of(value));
    }

    private ThreatSignal detect(SecurityAnalysisContext context) {
        return detector.detect(context).block();
    }

    private static void assertClean(ThreatSignal signal) {
        assertThat(signal.threatDetected()).isFalse();
        assertThat(signal.severity()).isEqualTo(0.0);
    }

    private static void assertThreatAtLeastThreshold(ThreatSignal signal) {
        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isGreaterThanOrEqualTo(0.9);
    }

    // --- 1. <script> tag payloads ----------------------------------------------------------

    @Test
    void detectsScriptTagInQueryParameter() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "<script>alert(1)</script>")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.detectorName()).isEqualTo("xss");
        assertThat(signal.description()).contains("script_tag");
    }

    // --- 2. URL-encoded <script> -------------------------------------------------------------

    @Test
    void detectsUrlEncodedScriptTag() {
        // "<script>alert(1)</script>" with "<" and ">" percent-encoded.
        String encoded = "%3Cscript%3Ealert(1)%3C/script%3E";

        ThreatSignal signal = detect(context("/api/search", queryParam("q", encoded)));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("script_tag");
    }

    // --- 3. HTML-entity encoded <script> ------------------------------------------------------

    @Test
    void detectsHtmlEntityEncodedScriptTagNamedEntities() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "&lt;script&gt;alert(1)&lt;/script&gt;")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("script_tag");
    }

    @Test
    void detectsHtmlEntityEncodedScriptTagNumericDecimalEntities() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "&#60;script&#62;alert(1)&#60;/script&#62;")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("script_tag");
    }

    @Test
    void detectsHtmlEntityEncodedScriptTagNumericHexEntities() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "&#x3C;script&#x3E;alert(1)")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("script_tag");
    }

    // --- 4. event-handler attacks --------------------------------------------------------------

    @Test
    void detectsOnErrorEventHandler() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "<img src=x onerror=alert(1)>")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("event_handler");
    }

    @Test
    void detectsOnLoadEventHandler() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "<body onload=alert(1)>")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("event_handler");
    }

    @Test
    void detectsOnClickEventHandlerWithQuotedValue() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "onclick=\"alert(1)\"")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("event_handler");
    }

    // --- 5. javascript: URLs ---------------------------------------------------------------------

    @Test
    void detectsJavascriptUrlScheme() {
        ThreatSignal signal = detect(context("/api/search", queryParam("redirect", "javascript:alert(1)")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("javascript_url");
    }

    // --- 6. iframe/object/embed attacks -----------------------------------------------------------

    @Test
    void detectsIframeInjection() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "<iframe src=\"javascript:alert(1)\">")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("dangerous_frame_tag");
    }

    @Test
    void detectsObjectInjection() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "<object data=\"evil.swf\"></object>")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("dangerous_frame_tag");
    }

    @Test
    void detectsEmbedInjection() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "<embed src=\"evil.swf\">")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("dangerous_frame_tag");
    }

    // --- 7. SVG attacks ------------------------------------------------------------------------------

    @Test
    void detectsSvgOnloadInjection() {
        ThreatSignal signal = detect(context("/api/search", queryParam("q", "<svg onload=alert(1)>")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("svg_injection");
    }

    // --- 8. attribute-breaking attacks -----------------------------------------------------------------

    @Test
    void detectsQuoteBreakoutIntoEventHandler() {
        ThreatSignal signal = detect(context("/api/search", queryParam("name", "\" onmouseover=\"alert(1)")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("attribute_breakout");
    }

    @Test
    void detectsQuoteBreakoutIntoNewTag() {
        ThreatSignal signal = detect(context("/api/search", queryParam("name", "'><script>alert(1)</script>")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("attribute_breakout");
    }

    // --- 9. query parameter attacks (name and secondary param) --------------------------------------------

    @Test
    void detectsAttackInQueryParameterName() {
        ThreatSignal signal = detect(context("/api/search", Map.of("<script>alert(1)</script>", List.of("x"))));

        assertThreatAtLeastThreshold(signal);
    }

    @Test
    void detectsAttackInSecondaryQueryParameterAmongMultiple() {
        ThreatSignal signal = detect(context("/api/search",
                Map.of("q", List.of("laptop"), "ref", List.of("<script>alert(1)</script>"))));

        assertThreatAtLeastThreshold(signal);
    }

    // --- 10. path attacks -----------------------------------------------------------------------------------

    @Test
    void detectsAttackInUrlPath() {
        ThreatSignal signal = detect(context("/api/users/<script>alert(1)</script>", Map.of()));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("script_tag");
    }

    // --- 11. Referer header ---------------------------------------------------------------------------------

    @Test
    void detectsXssInRefererHeader() {
        ThreatSignal signal = detect(contextWithHeader("Referer", "http://evil.example/?q=<script>alert(1)</script>"));

        assertThreatAtLeastThreshold(signal);
    }

    // --- 12. X-Forwarded-For header --------------------------------------------------------------------------

    @Test
    void detectsXssInXForwardedForHeader() {
        ThreatSignal signal = detect(contextWithHeader("X-Forwarded-For", "<script>alert(1)</script>"));

        assertThreatAtLeastThreshold(signal);
    }

    @Test
    void ignoresUnrelatedHeaders() {
        ThreatSignal signal = detect(contextWithHeader("User-Agent", "<script>alert(1)</script>"));

        assertClean(signal);
    }

    // --- 13. case variations ---------------------------------------------------------------------------------

    @Test
    void detectsUpperCaseScriptTag() {
        assertThreatAtLeastThreshold(detect(context("/api/search", queryParam("q", "<SCRIPT>alert(1)</SCRIPT>"))));
    }

    @Test
    void detectsMixedCaseScriptTag() {
        assertThreatAtLeastThreshold(detect(context("/api/search", queryParam("q", "<ScRiPt>alert(1)</ScRiPt>"))));
    }

    @Test
    void detectsUpperCaseEventHandler() {
        assertThreatAtLeastThreshold(detect(context("/api/search", queryParam("q", "<img src=x ONCLICK=alert(1)>"))));
    }

    // --- 14/15/16. legitimate text that must remain clean ---------------------------------------------------

    @Test
    void legitimateJavaScriptTutorialTextIsClean() {
        assertClean(detect(context("/api/search", queryParam("q", "JavaScript tutorial for beginners"))));
    }

    @Test
    void legitimateScriptWritingTextIsClean() {
        assertClean(detect(context("/api/search", queryParam("q", "how to write a script for the school play"))));
    }

    @Test
    void legitimateOnclickDocumentationTextIsClean() {
        assertClean(detect(context("/api/search", queryParam("q", "onclick documentation and examples"))));
    }

    @Test
    void apostropheNameOBrienIsClean() {
        assertClean(detect(context("/api/users", queryParam("name", "O'Brien"))));
    }

    // --- 17. normal API requests -------------------------------------------------------------------------------

    @Test
    void plainUsersPathWithNoQueryIsClean() {
        assertClean(detect(context("/api/users/1", Map.of())));
    }

    @Test
    void ordinaryPaginationQueryParamsAreClean() {
        assertClean(detect(context("/api/users", Map.of("page", List.of("2"), "size", List.of("10")))));
    }

    // --- 18. multiple matched categories increase severity -------------------------------------------------------

    @Test
    void multipleMatchedCategoriesIncreaseSeverityAboveSingleMatch() {
        ThreatSignal singleCategory = detect(context("/api/search", queryParam("q", "<script>alert(1)</script>")));
        ThreatSignal multiCategory = detect(context("/api/search",
                queryParam("q", "<img src=x onerror=alert(1)><script>alert(2)</script>")));

        assertThat(multiCategory.threatDetected()).isTrue();
        assertThat(multiCategory.severity()).isGreaterThan(singleCategory.severity());
        assertThat(multiCategory.description()).contains("script_tag").contains("event_handler");
        assertThat(multiCategory.severity()).isLessThanOrEqualTo(1.0);
    }

    // --- 19. detector always returns a ThreatSignal ---------------------------------------------------------------

    @Test
    void alwaysReturnsExactlyOneSignalForMaliciousInput() {
        StepVerifier.create(detector.detect(context("/api/search", queryParam("q", "<script>alert(1)</script>"))))
                .expectNextCount(1)
                .verifyComplete();
    }

    @Test
    void alwaysReturnsExactlyOneSignalForCleanInput() {
        StepVerifier.create(detector.detect(context("/api/users/1", Map.of())))
                .expectNextCount(1)
                .verifyComplete();
    }

    // --- 20. reactive behavior ---------------------------------------------------------------------------------------

    @Test
    void detectReturnsAMonoWithoutThrowingSynchronously() {
        Mono<ThreatSignal> result = detector.detect(context("/api/search", queryParam("q", "<script>alert(1)</script>")));

        StepVerifier.create(result)
                .assertNext(signal -> assertThat(signal.threatDetected()).isTrue())
                .verifyComplete();
    }
}
