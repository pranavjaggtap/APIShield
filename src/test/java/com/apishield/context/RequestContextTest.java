package com.apishield.context;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestContextTest {

    private static RequestContext context(Map<String, List<String>> headers, Map<String, List<String>> queryParams) {
        return new RequestContext("req-1", "GET", "/api/users/1", headers, queryParams, "127.0.0.1",
                Instant.parse("2026-01-01T00:00:00Z"), Optional.empty(), Optional.empty());
    }

    @Test
    void headerLookupIsCaseInsensitive() {
        RequestContext context = context(Map.of("user-agent", List.of("curl/8.0")), Map.of());

        assertThat(context.headers().get("User-Agent")).containsExactly("curl/8.0");
        assertThat(context.headers().get("USER-AGENT")).containsExactly("curl/8.0");
    }

    @Test
    void queryParamLookupRemainsCaseSensitive() {
        RequestContext context = context(Map.of(), Map.of("id", List.of("1")));

        assertThat(context.queryParams().get("id")).containsExactly("1");
        assertThat(context.queryParams().get("ID")).isNull();
    }

    @Test
    void mapsAndValueListsAreUnmodifiable() {
        RequestContext context = context(Map.of("Accept", List.of("*/*")), Map.of("id", List.of("1")));

        assertThatThrownBy(() -> context.headers().put("X-New", List.of("v")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> context.headers().get("Accept").add("text/html"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> context.queryParams().put("q", List.of("v")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> context.queryParams().get("id").add("2"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void laterMutationOfSourceMapsDoesNotLeakIntoContext() {
        List<String> acceptValues = new ArrayList<>(List.of("*/*"));
        Map<String, List<String>> headers = new HashMap<>(Map.of("Accept", acceptValues));
        List<String> idValues = new ArrayList<>(List.of("1"));
        Map<String, List<String>> queryParams = new HashMap<>(Map.of("id", idValues));

        RequestContext context = context(headers, queryParams);
        headers.put("X-Injected", List.of("v"));
        acceptValues.add("text/html");
        queryParams.put("q", List.of("v"));
        idValues.add("2");

        assertThat(context.headers()).containsOnlyKeys("Accept");
        assertThat(context.headers().get("Accept")).containsExactly("*/*");
        assertThat(context.queryParams()).containsOnlyKeys("id");
        assertThat(context.queryParams().get("id")).containsExactly("1");
    }

    @Test
    void valuelessQueryParameterNullValueIsPreserved() {
        RequestContext context = context(Map.of(), Map.of("flag", Arrays.asList((String) null)));

        assertThat(context.queryParams().get("flag")).containsExactly((String) null);
    }

    @Test
    void routeAndUserIdAreOptional() {
        RequestContext anonymous = context(Map.of(), Map.of());
        assertThat(anonymous.route()).isEmpty();
        assertThat(anonymous.userId()).isEmpty();

        RouteInfo route = new RouteInfo("user-service", URI.create("http://localhost:8081"));
        RequestContext routed = new RequestContext("req-1", "GET", "/api/users/1", Map.of(), Map.of(), "127.0.0.1",
                Instant.now(), Optional.of(route), Optional.of("user-42"));
        assertThat(routed.route()).contains(route);
        assertThat(routed.userId()).contains("user-42");
    }

    @Test
    void requiredFieldsRejectNull() {
        assertThatThrownBy(() -> new RequestContext(null, "GET", "/", Map.of(), Map.of(), "127.0.0.1",
                Instant.now(), Optional.empty(), Optional.empty()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new RequestContext("req-1", "GET", "/", null, Map.of(), "127.0.0.1",
                Instant.now(), Optional.empty(), Optional.empty()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new RequestContext("req-1", "GET", "/", Map.of(), Map.of(), "127.0.0.1",
                Instant.now(), null, Optional.empty()))
                .isInstanceOf(NullPointerException.class);
    }
}
