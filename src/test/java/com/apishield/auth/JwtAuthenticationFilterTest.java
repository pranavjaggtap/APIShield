package com.apishield.auth;

import com.apishield.context.RequestContext;
import com.apishield.context.RequestContextAttributes;
import com.apishield.context.RequestContextFactory;
import com.apishield.context.RequestContextFilter;
import com.apishield.security.SecurityGatewayFilter;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationFilterTest {

    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(TestJwts.decoder());

    // --- helpers -----------------------------------------------------------------------

    /** Mirrors what RequestContextFilter does earlier in the real filter chain. */
    private static MockServerWebExchange exchange(String authorizationHeader) {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/api/users/1")
                .header("User-Agent", "curl/8.0");
        if (authorizationHeader != null) {
            request.header(HttpHeaders.AUTHORIZATION, authorizationHeader);
        }
        MockServerWebExchange exchange = MockServerWebExchange.from(request.build());
        RequestContextAttributes.put(exchange, new RequestContextFactory().create(exchange));
        return exchange;
    }

    private static GatewayFilterChain recordingChain(AtomicBoolean chainCalled) {
        return ex -> {
            chainCalled.set(true);
            return Mono.empty();
        };
    }

    private void assertRejectedWith401(MockServerWebExchange exchange, String expectedWwwAuthenticate) {
        assertRejectedWith401(filter, exchange, expectedWwwAuthenticate);
    }

    private static void assertRejectedWith401(JwtAuthenticationFilter filter, MockServerWebExchange exchange,
                                              String expectedWwwAuthenticate) {
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, recordingChain(chainCalled)))
                .verifyComplete();

        assertThat(chainCalled.get()).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .startsWith(expectedWwwAuthenticate);
        assertThat(RequestContextAttributes.require(exchange).userId()).isEmpty();
    }

    // --- valid token -----------------------------------------------------------------------

    @Test
    void validTokenInvokesChainWithoutWritingAResponse() {
        MockServerWebExchange exchange = exchange("Bearer " + TestJwts.validToken("user-42"));
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, recordingChain(chainCalled)))
                .verifyComplete();

        assertThat(chainCalled.get()).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void userIdIsExtractedFromSubClaimIntoRequestContext() {
        MockServerWebExchange exchange = exchange("Bearer " + TestJwts.validToken("user-42"));
        AtomicReference<RequestContext> seenByChain = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            seenByChain.set(RequestContextAttributes.require(ex));
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(seenByChain.get().userId()).contains("user-42");
        assertThat(RequestContextAttributes.require(exchange).userId()).contains("user-42");
    }

    @Test
    void authenticatedContextIsANewInstanceAndOtherwiseUnchanged() {
        MockServerWebExchange exchange = exchange("Bearer " + TestJwts.validToken("user-42"));
        RequestContext original = RequestContextAttributes.require(exchange);

        StepVerifier.create(filter.filter(exchange, recordingChain(new AtomicBoolean())))
                .verifyComplete();

        RequestContext authenticated = RequestContextAttributes.require(exchange);
        assertThat(authenticated).isNotSameAs(original);
        assertThat(original.userId()).isEmpty();
        assertThat(authenticated.requestId()).isEqualTo(original.requestId());
        assertThat(authenticated.path()).isEqualTo(original.path());
        assertThat(authenticated.headers()).isEqualTo(original.headers());
        assertThat(authenticated.clientIp()).isEqualTo(original.clientIp());
        assertThat(authenticated.timestamp()).isEqualTo(original.timestamp());
    }

    @Test
    void rawTokenNeverEntersRequestContext() {
        String token = TestJwts.validToken("user-42");
        MockServerWebExchange exchange = exchange("Bearer " + token);

        StepVerifier.create(filter.filter(exchange, recordingChain(new AtomicBoolean())))
                .verifyComplete();

        RequestContext context = RequestContextAttributes.require(exchange);
        assertThat(context.headers()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
        assertThat(context.toString()).doesNotContain(token);
    }

    @Test
    void authenticationIsPublishedToReactiveSecurityContextForDownstreamFilters() {
        MockServerWebExchange exchange = exchange("Bearer " + TestJwts.validToken("user-42"));
        AtomicReference<Authentication> seenByChain = new AtomicReference<>();
        GatewayFilterChain chain = ex -> ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .doOnNext(seenByChain::set)
                .then();

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(seenByChain.get()).isInstanceOf(JwtAuthenticationToken.class);
        assertThat(seenByChain.get().getName()).isEqualTo("user-42");
    }

    // --- missing token -------------------------------------------------------------------

    @Test
    void missingAuthorizationHeaderIsRejectedWithoutErrorCode() {
        MockServerWebExchange exchange = exchange(null);

        assertRejectedWith401(exchange, "Bearer");
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .doesNotContain("error=");
    }

    @Test
    void nonBearerSchemeIsTreatedAsMissingToken() {
        MockServerWebExchange exchange = exchange("Basic dXNlcjpwYXNz");

        assertRejectedWith401(exchange, "Bearer");
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .doesNotContain("error=");
    }

    // --- invalid tokens --------------------------------------------------------------------

    @Test
    void malformedBearerHeaderIsRejectedAsInvalidToken() {
        assertRejectedWith401(exchange("Bearer !!!not a token!!!"), "Bearer error=\"invalid_token\"");
    }

    @Test
    void malformedJwtIsRejectedAsInvalidToken() {
        assertRejectedWith401(exchange("Bearer not.a.jwt"), "Bearer error=\"invalid_token\"");
    }

    @Test
    void expiredJwtIsRejectedAsInvalidToken() {
        assertRejectedWith401(exchange("Bearer " + TestJwts.expiredToken("user-42")), "Bearer error=\"invalid_token\"");
    }

    @Test
    void jwtWithInvalidSignatureIsRejectedAsInvalidToken() {
        assertRejectedWith401(exchange("Bearer " + TestJwts.tokenSignedByUntrustedKey("user-42")),
                "Bearer error=\"invalid_token\"");
    }

    @Test
    void jwtWithoutSubClaimIsRejectedAsInvalidToken() {
        assertRejectedWith401(exchange("Bearer " + TestJwts.tokenWithoutSubject()), "Bearer error=\"invalid_token\"");
    }

    // --- no decoder configured: 401, never 500, never routed -----------------------------------

    private final JwtAuthenticationFilter unconfigured = new JwtAuthenticationFilter((ReactiveJwtDecoder) null);

    @Test
    void noDecoderAndNoAuthorizationHeaderIsRejectedWith401() {
        MockServerWebExchange exchange = exchange(null);

        assertRejectedWith401(unconfigured, exchange, "Bearer");
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .doesNotContain("error=");
    }

    @Test
    void noDecoderAndNonBearerSchemeIsRejectedWith401() {
        MockServerWebExchange exchange = exchange("Basic dXNlcjpwYXNz");

        assertRejectedWith401(unconfigured, exchange, "Bearer");
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .doesNotContain("error=");
    }

    @Test
    void noDecoderRejectsEvenAWellFormedTokenWith401InvalidToken() {
        MockServerWebExchange exchange = exchange("Bearer " + TestJwts.validToken("user-42"));

        assertRejectedWith401(unconfigured, exchange, "Bearer error=\"invalid_token\"");
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .as("must not reveal server configuration to clients")
                .doesNotContainIgnoringCase("decoder");
    }

    @Test
    void missingRequestContextFailsClosedWithoutRouting() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/users/1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("user-42"))
                .build());
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, recordingChain(chainCalled)))
                .expectError(IllegalStateException.class)
                .verify();

        assertThat(chainCalled.get()).isFalse();
    }

    // --- ordering ------------------------------------------------------------------------------

    @Test
    void runsBetweenRequestContextFilterAndSecurityGatewayFilter() {
        assertThat(RequestContextFilter.ORDER).isLessThan(JwtAuthenticationFilter.ORDER);
        assertThat(JwtAuthenticationFilter.ORDER).isLessThan(SecurityGatewayFilter.ORDER);
        assertThat(filter.getOrder()).isEqualTo(JwtAuthenticationFilter.ORDER);
    }
}
