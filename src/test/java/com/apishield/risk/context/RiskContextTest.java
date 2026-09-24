package com.apishield.risk.context;

import com.apishield.context.RequestContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RiskContextTest {

    private record ExampleInput(int value) implements ContextualInput {
    }

    private final RequestContext request = new RequestContext("req-1", "GET", "/api/users/1", Map.of(), Map.of(),
            "127.0.0.1", Instant.now(), Optional.empty(), Optional.of("user-42"));

    @Test
    void withoutInputsCarriesRequestAndEmptyInputs() {
        RiskContext context = RiskContext.withoutInputs(request);

        assertThat(context.request()).isSameAs(request);
        assertThat(context.inputs().isEmpty()).isTrue();
    }

    @Test
    void emptyInputsReturnNothingForAnyType() {
        assertThat(ContextualInputs.empty().get(ExampleInput.class)).isEmpty();
    }

    @Test
    void rejectsNulls() {
        assertThatThrownBy(() -> new RiskContext(null, ContextualInputs.empty()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new RiskContext(request, null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> ContextualInputs.empty().get(null))
                .isInstanceOf(NullPointerException.class);
    }
}
