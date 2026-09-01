package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SqlInjectionDetectorTest {

    private final SqlInjectionDetector detector = new SqlInjectionDetector();

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

    // --- 1. clearly malicious examples --------------------------------------------------

    @Test
    void detectsTautologyAuthBypassInQueryParameter() {
        ThreatSignal signal = detect(context("/api/users/1", queryParam("id", "1' OR '1'='1")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("tautology");
    }

    @Test
    void detectsUnionSelectInQueryParameter() {
        ThreatSignal signal = detect(context("/api/users/1",
                queryParam("id", "1 UNION SELECT username, password FROM users")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("union_select");
    }

    @Test
    void detectsTrailingSqlCommentMarker() {
        ThreatSignal signal = detect(context("/api/users/1", queryParam("username", "admin'--")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("sql_comment");
    }

    @Test
    void detectsBlockCommentMarker() {
        ThreatSignal signal = detect(context("/api/users/1", queryParam("id", "1/*comment*/OR/**/1=1")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("sql_comment");
    }

    @Test
    void detectsStackedQuery() {
        ThreatSignal signal = detect(context("/api/users/1", queryParam("id", "1; DROP TABLE users")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("stacked_query");
    }

    @Test
    void detectsTimeBasedBlindSqlInjection() {
        ThreatSignal signal = detect(context("/api/users/1", queryParam("id", "1 OR SLEEP(5)")));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("time_based");
    }

    // --- 2. URL-encoded malicious input --------------------------------------------------

    @Test
    void detectsUrlEncodedSqlInjectionInQueryParameter() {
        // "1' OR '1'='1" with the quotes/space/equals percent-encoded, as if this value
        // reached the detector still encoded.
        String encoded = "1%27%20OR%20%271%27%3D%271";

        ThreatSignal signal = detect(context("/api/users/1", queryParam("id", encoded)));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("tautology");
    }

    // --- double-encoded malicious input ---------------------------------------------------

    @Test
    void detectsDoubleEncodedSqlInjectionAsPresentedAfterSpringsAutomaticFirstDecode() {
        String plaintext = "1' OR '1'='1";
        String trulyDoubleEncoded = URLEncoder.encode(
                URLEncoder.encode(plaintext, StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        // Spring's own query-parameter parsing performs one decode pass automatically before
        // this detector ever sees the value; simulate exactly that post-Spring-decode state.
        String asSpringWouldPresentIt = URLDecoder.decode(trulyDoubleEncoded, StandardCharsets.UTF_8);
        assertThat(asSpringWouldPresentIt).isNotEqualTo(plaintext); // still one level encoded

        ThreatSignal signal = detect(context("/api/users/1", queryParam("id", asSpringWouldPresentIt)));

        assertThreatAtLeastThreshold(signal);
        assertThat(signal.description()).contains("tautology");
    }

    // --- 3. query parameter attacks -------------------------------------------------------

    @Test
    void detectsAttackInSecondaryQueryParameterAmongMultiple() {
        ThreatSignal signal = detect(context("/api/search",
                Map.of("q", List.of("laptop"), "filter", List.of("1' OR '1'='1"))));

        assertThreatAtLeastThreshold(signal);
    }

    @Test
    void detectsAttackInQueryParameterName() {
        ThreatSignal signal = detect(context("/api/users", Map.of("1 UNION SELECT 1", List.of("x"))));

        assertThreatAtLeastThreshold(signal);
    }

    // --- header inspection -----------------------------------------------------------------

    @Test
    void detectsSqlInjectionInXForwardedForHeader() {
        ThreatSignal signal = detect(contextWithHeader("X-Forwarded-For", "1' UNION SELECT 1--"));

        assertThreatAtLeastThreshold(signal);
    }

    @Test
    void detectsSqlInjectionInRefererHeader() {
        ThreatSignal signal = detect(contextWithHeader("Referer", "http://evil.example/?id=1' OR '1'='1"));

        assertThreatAtLeastThreshold(signal);
    }

    @Test
    void ignoresUnrelatedHeaders() {
        ThreatSignal signal = detect(contextWithHeader("User-Agent", "1' OR '1'='1"));

        assertClean(signal);
    }

    // --- 4. clearly normal requests --------------------------------------------------------

    @Test
    void plainUsersPathWithNoQueryIsClean() {
        assertClean(detect(context("/api/users/1", Map.of())));
    }

    @Test
    void ordinaryPaginationQueryParamsAreClean() {
        assertClean(detect(context("/api/users", Map.of("page", List.of("2"), "size", List.of("10")))));
    }

    // --- 5. false-positive-prone normal values ---------------------------------------------

    @Test
    void apostropheNameOBrienIsClean() {
        assertClean(detect(context("/api/users", queryParam("name", "O'Brien"))));
    }

    @Test
    void ordinaryEnglishContainingSelectionIsClean() {
        assertClean(detect(context("/api/search", queryParam("q", "product selection guide"))));
    }

    @Test
    void ordinaryEnglishContainingDropShippingIsClean() {
        assertClean(detect(context("/api/search", queryParam("q", "drop shipping suppliers"))));
    }

    @Test
    void informalEmDashUsageIsClean() {
        assertClean(detect(context("/api/search", queryParam("comment", "see you soon -- take care"))));
    }

    @Test
    void semicolonWithoutKeywordIsClean() {
        assertClean(detect(context("/api/search", queryParam("q", "widgets; gadgets; gizmos"))));
    }

    // --- 6. multiple suspicious patterns ----------------------------------------------------

    @Test
    void multipleMatchedCategoriesIncreaseSeverityAboveSingleMatch() {
        ThreatSignal singleCategory = detect(context("/api/users/1", queryParam("id", "1 OR SLEEP(5)")));
        ThreatSignal multiCategory = detect(context("/api/users/1", queryParam("id", "1' OR '1'='1' --")));

        assertThat(multiCategory.threatDetected()).isTrue();
        assertThat(multiCategory.severity()).isGreaterThan(singleCategory.severity());
        assertThat(multiCategory.description()).contains("tautology").contains("sql_comment");
        assertThat(multiCategory.severity()).isLessThanOrEqualTo(1.0);
    }

    // --- 7. detector always returns a ThreatSignal ------------------------------------------

    @Test
    void alwaysReturnsExactlyOneSignalForMaliciousInput() {
        StepVerifier.create(detector.detect(context("/api/users/1", queryParam("id", "1' OR '1'='1"))))
                .expectNextCount(1)
                .verifyComplete();
    }

    @Test
    void alwaysReturnsExactlyOneSignalForCleanInput() {
        StepVerifier.create(detector.detect(context("/api/users/1", Map.of())))
                .expectNextCount(1)
                .verifyComplete();
    }

    // --- 8. reactive behavior ----------------------------------------------------------------

    @Test
    void detectReturnsAMonoWithoutThrowingSynchronously() {
        Mono<ThreatSignal> result = detector.detect(context("/api/users/1", queryParam("id", "1' OR '1'='1")));

        StepVerifier.create(result)
                .assertNext(signal -> assertThat(signal.threatDetected()).isTrue())
                .verifyComplete();
    }
}
