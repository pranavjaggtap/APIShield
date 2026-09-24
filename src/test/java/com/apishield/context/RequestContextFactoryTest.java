package com.apishield.context;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class RequestContextFactoryTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-01-01T12:00:00Z");

    private final RequestContextFactory factory = new RequestContextFactory(Clock.fixed(FIXED_NOW, ZoneOffset.UTC));

    @Test
    void capturesCoreRequestFacts() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/users/1")
                        .queryParam("q", "hello")
                        .header("User-Agent", "curl/8.0")
                        .remoteAddress(new InetSocketAddress("10.0.0.5", 54321))
                        .build());

        RequestContext context = factory.create(exchange);

        assertThat(context.requestId()).isEqualTo(exchange.getRequest().getId());
        assertThat(context.method()).isEqualTo("POST");
        assertThat(context.path()).isEqualTo("/api/users/1");
        assertThat(context.queryParams().get("q")).containsExactly("hello");
        assertThat(context.headers().get("User-Agent")).containsExactly("curl/8.0");
        assertThat(context.clientIp()).isEqualTo("10.0.0.5");
        assertThat(context.timestamp()).isEqualTo(FIXED_NOW);
    }

    @Test
    void queryParamsAreDecodedExactlyAsTheRequestExposesThem() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users?id=1%27%20OR%20%271%27%3D%271&flag").build());

        RequestContext context = factory.create(exchange);

        assertThat(context.queryParams()).isEqualTo(exchange.getRequest().getQueryParams());
    }

    @Test
    void clientIpFallsBackToUnknownWithoutRemoteAddress() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/users/1").build());

        assertThat(factory.create(exchange).clientIp()).isEqualTo("unknown");
    }

    @Test
    void xForwardedForIsKeptAsHeaderButNeverUsedAsClientIp() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/1")
                        .header("X-Forwarded-For", "203.0.113.9")
                        .remoteAddress(new InetSocketAddress("10.0.0.5", 54321))
                        .build());

        RequestContext context = factory.create(exchange);

        assertThat(context.clientIp()).isEqualTo("10.0.0.5");
        assertThat(context.headers().get("X-Forwarded-For")).containsExactly("203.0.113.9");
    }

    @Test
    void credentialBearingHeadersAreExcluded() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/1")
                        .header("Authorization", "Bearer secret-token")
                        .header("proxy-authorization", "Basic c2VjcmV0")
                        .header("Cookie", "SESSION=abc")
                        .header("Accept", "application/json")
                        .build());

        RequestContext context = factory.create(exchange);

        assertThat(context.headers()).doesNotContainKeys("Authorization", "Proxy-Authorization", "Cookie");
        assertThat(context.headers().get("Accept")).containsExactly("application/json");
    }

    @Test
    void lowerCaseHeaderNamesRemainLookupCompatible() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/1")
                        .header("user-agent", "node-fetch/1.0")
                        .header("x-apishield-nonce", "abc-123")
                        .build());

        RequestContext context = factory.create(exchange);

        assertThat(context.headers().get("User-Agent")).containsExactly("node-fetch/1.0");
        assertThat(context.headers().get("X-APIShield-Nonce")).containsExactly("abc-123");
    }

    @Test
    void capturesMatchedGatewayRoute() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/users/1").build());
        Route route = Route.async()
                .id("user-service")
                .uri(URI.create("http://localhost:8081"))
                .predicate(ex -> true)
                .build();
        exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, route);

        RequestContext context = factory.create(exchange);

        assertThat(context.route()).contains(new RouteInfo("user-service", URI.create("http://localhost:8081")));
    }

    @Test
    void routeIsEmptyWhenNoRouteMatched() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/users/1").build());

        assertThat(factory.create(exchange).route()).isEmpty();
    }

    @Test
    void userIdIsEmptyUntilAuthenticationExists() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/users/1").header("Authorization", "Bearer token").build());

        assertThat(factory.create(exchange).userId()).isEmpty();
    }
}
