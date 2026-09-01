package com.apishield.threat;

import com.apishield.model.SecurityAnalysisContext;
import com.apishield.model.ThreatSignal;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class BotAutomationDetectorTest {

    private final BotAutomationDetector detector = new BotAutomationDetector();

    // --- helpers -----------------------------------------------------------------------

    private static SecurityAnalysisContext context(Map<String, List<String>> headers) {
        return new SecurityAnalysisContext("req-1", "GET", "/api/users/1", headers, Map.of(), "127.0.0.1", Instant.now());
    }

    private static Map<String, List<String>> headers(String userAgent, String accept, String acceptLanguage,
                                                       String acceptEncoding) {
        Map<String, List<String>> headers = new HashMap<>();
        if (userAgent != null) {
            headers.put("User-Agent", List.of(userAgent));
        }
        if (accept != null) {
            headers.put("Accept", List.of(accept));
        }
        if (acceptLanguage != null) {
            headers.put("Accept-Language", List.of(acceptLanguage));
        }
        if (acceptEncoding != null) {
            headers.put("Accept-Encoding", List.of(acceptEncoding));
        }
        return headers;
    }

    private static final String FULL_BROWSER_ACCEPT = "text/html,application/xhtml+xml";
    private static final String FULL_BROWSER_ACCEPT_LANGUAGE = "en-US,en;q=0.9";
    private static final String FULL_BROWSER_ACCEPT_ENCODING = "gzip, deflate, br";
    private static final String REALISTIC_CHROME_UA =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    private ThreatSignal detect(SecurityAnalysisContext context) {
        return detector.detect(context).block();
    }

    // --- missing / blank User-Agent -------------------------------------------------------

    @Test
    void missingUserAgentIsFlagged() {
        ThreatSignal signal = detect(context(headers(null,
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.3);
        assertThat(signal.detectorName()).isEqualTo("bot-automation");
        assertThat(signal.description()).contains("missing_user_agent");
    }

    @Test
    void blankUserAgentIsFlaggedSameAsMissing() {
        ThreatSignal signal = detect(context(headers("   ",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.3);
        assertThat(signal.description()).contains("missing_user_agent");
    }

    // --- known automation tools -------------------------------------------------------------

    @Test
    void curlUserAgentIsFlagged() {
        ThreatSignal signal = detect(context(headers("curl/8.4.0",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.2);
        assertThat(signal.description()).contains("known_automation_tool");
    }

    @Test
    void plainCurlWithDefaultHeadersScoresExactlyPointTwoAndStaysUnderBlockThreshold() {
        // Default curl: sends "curl/x.y.z" UA and "Accept: */*", but no Accept-Language or
        // Accept-Encoding by default - the calibration this project's own E2E testing relies on.
        ThreatSignal signal = detect(context(headers("curl/8.4.0", "*/*", null, null)));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.2);
        assertThat(signal.severity()).isLessThan(0.5);
    }

    @Test
    void pythonRequestsUserAgentIsFlagged() {
        ThreatSignal signal = detect(context(headers("python-requests/2.31.0",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.2);
        assertThat(signal.description()).contains("known_automation_tool");
    }

    @Test
    void postmanRuntimeUserAgentIsFlagged() {
        ThreatSignal signal = detect(context(headers("PostmanRuntime/7.32.0",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.2);
    }

    @Test
    void goHttpClientUserAgentIsFlagged() {
        ThreatSignal signal = detect(context(headers("Go-http-client/1.1",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.2);
    }

    @Test
    void botCrawlerSpiderSubstringsAreFlagged() {
        ThreatSignal botSignal = detect(context(headers("SomeBot/1.0",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));
        ThreatSignal crawlerSignal = detect(context(headers("ExampleCrawler/2.0",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));
        ThreatSignal spiderSignal = detect(context(headers("WebSpider/3.0",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(botSignal.threatDetected()).isTrue();
        assertThat(crawlerSignal.threatDetected()).isTrue();
        assertThat(spiderSignal.threatDetected()).isTrue();
    }

    // --- case-insensitive matching -----------------------------------------------------------

    @Test
    void automationToolMatchingIsCaseInsensitive() {
        ThreatSignal upperCase = detect(context(headers("CURL/8.0.0",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));
        ThreatSignal mixedCase = detect(context(headers("Python-Requests/2.31.0",
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(upperCase.threatDetected()).isTrue();
        assertThat(upperCase.description()).contains("known_automation_tool");
        assertThat(mixedCase.threatDetected()).isTrue();
        assertThat(mixedCase.description()).contains("known_automation_tool");
    }

    // --- realistic browser is clean ------------------------------------------------------------

    @Test
    void realisticBrowserHeadersAreClean() {
        ThreatSignal signal = detect(context(headers(REALISTIC_CHROME_UA,
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(signal.threatDetected()).isFalse();
        assertThat(signal.severity()).isEqualTo(0.0);
        assertThat(signal.description()).isEqualTo("no bot/automation signals matched");
    }

    // --- calibration: missing UA + all three browser headers = exactly 0.5 -----------------------

    @Test
    void missingUserAgentAndAllThreeBrowserHeadersScoresExactlyPointFiveAndWouldBlock() {
        ThreatSignal signal = detect(context(headers(null, null, null, null)));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.5);
        assertThat(signal.description()).contains("missing_user_agent").contains("missing_browser_headers");
    }

    // --- only one Accept* header missing does not fire missing_browser_headers ---------------------

    @Test
    void onlyAcceptLanguageMissingDoesNotFireBrowserHeadersRule() {
        ThreatSignal signal = detect(context(headers(REALISTIC_CHROME_UA,
                FULL_BROWSER_ACCEPT, null, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(signal.threatDetected()).isFalse();
        assertThat(signal.description()).doesNotContain("missing_browser_headers");
    }

    @Test
    void onlyAcceptMissingDoesNotFireBrowserHeadersRule() {
        ThreatSignal signal = detect(context(headers(REALISTIC_CHROME_UA,
                null, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING)));

        assertThat(signal.threatDetected()).isFalse();
    }

    // --- multiple categories: correct severity sum -----------------------------------------------

    @Test
    void knownToolPlusMissingBrowserHeadersSumsCorrectly() {
        ThreatSignal signal = detect(context(headers("curl/8.4.0", null, null, null)));

        assertThat(signal.threatDetected()).isTrue();
        assertThat(signal.severity()).isEqualTo(0.4);
        assertThat(signal.description()).contains("known_automation_tool").contains("missing_browser_headers");
    }

    // --- X-Forwarded-For must never affect the result ---------------------------------------------

    @Test
    void changingXForwardedForDoesNotChangeResult() {
        Map<String, List<String>> withXff1 = headers(REALISTIC_CHROME_UA,
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING);
        withXff1.put("X-Forwarded-For", List.of("1.2.3.4"));

        Map<String, List<String>> withXff2 = headers(REALISTIC_CHROME_UA,
                FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING);
        withXff2.put("X-Forwarded-For", List.of("9.9.9.9"));

        ThreatSignal signal1 = detect(context(withXff1));
        ThreatSignal signal2 = detect(context(withXff2));

        assertThat(signal1).isEqualTo(signal2);
        assertThat(signal1.threatDetected()).isFalse();
    }

    @Test
    void changingXForwardedForDoesNotChangeResultForFlaggedRequest() {
        Map<String, List<String>> withXff1 = headers("curl/8.4.0", null, null, null);
        withXff1.put("X-Forwarded-For", List.of("1.2.3.4"));

        Map<String, List<String>> withXff2 = headers("curl/8.4.0", null, null, null);
        withXff2.put("X-Forwarded-For", List.of("evil-spoofed-value"));

        ThreatSignal signal1 = detect(context(withXff1));
        ThreatSignal signal2 = detect(context(withXff2));

        assertThat(signal1).isEqualTo(signal2);
    }

    // --- exactly one ThreatSignal returned ---------------------------------------------------------

    @Test
    void alwaysReturnsExactlyOneSignalForCleanRequest() {
        StepVerifier.create(detector.detect(context(headers(REALISTIC_CHROME_UA,
                        FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING))))
                .expectNextCount(1)
                .verifyComplete();
    }

    @Test
    void alwaysReturnsExactlyOneSignalForFlaggedRequest() {
        StepVerifier.create(detector.detect(context(headers(null, null, null, null))))
                .expectNextCount(1)
                .verifyComplete();
    }

    // --- reactive contract ---------------------------------------------------------------------------

    @Test
    void detectReturnsReactiveMonoWithoutThrowingSynchronously() {
        StepVerifier.create(detector.detect(context(headers("curl/8.4.0",
                        FULL_BROWSER_ACCEPT, FULL_BROWSER_ACCEPT_LANGUAGE, FULL_BROWSER_ACCEPT_ENCODING))))
                .assertNext(signal -> assertThat(signal.threatDetected()).isTrue())
                .verifyComplete();
    }

    // --- no Redis dependency -----------------------------------------------------------------------------

    @Test
    void detectorHasNoRedisDependency() {
        // Structural proof: the detector is constructible with zero arguments - unlike
        // ReplayAttackDetector/FrequencyAbuseDetector, which both require a
        // ReactiveStringRedisTemplate constructor argument.
        assertThat(new BotAutomationDetector()).isNotNull();
    }
}
