package com.apishield.context;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestContextAttributesTest {

    private final RequestContext context = new RequestContext("req-1", "GET", "/api/users/1", Map.of(), Map.of(),
            "127.0.0.1", Instant.now(), Optional.empty(), Optional.empty());

    private final MockServerWebExchange exchange =
            MockServerWebExchange.from(MockServerHttpRequest.get("/api/users/1").build());

    @Test
    void storedContextIsRetrievable() {
        RequestContextAttributes.put(exchange, context);

        assertThat(RequestContextAttributes.get(exchange)).containsSame(context);
        assertThat(RequestContextAttributes.require(exchange)).isSameAs(context);
    }

    @Test
    void storedUnderDocumentedAttributeName() {
        RequestContextAttributes.put(exchange, context);

        assertThat(exchange.getAttributes().get(RequestContextAttributes.ATTRIBUTE_NAME)).isSameAs(context);
    }

    @Test
    void getIsEmptyWhenNothingStored() {
        assertThat(RequestContextAttributes.get(exchange)).isEmpty();
    }

    @Test
    void requireThrowsWhenNothingStored() {
        assertThatThrownBy(() -> RequestContextAttributes.require(exchange))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("RequestContextFilter");
    }
}
