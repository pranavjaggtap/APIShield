package com.apishield.risk.context;

import com.apishield.risk.RiskTestContexts;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientKeyTest {

    @Test
    void authenticatedRequestIsKeyedByUser() {
        ClientKey key = ClientKey.of(RiskTestContexts.authenticated("alice"));

        assertThat(key).isEqualTo(new ClientKey(ClientKey.Kind.USER, "alice"));
        assertThat(key.asString()).isEqualTo("user:alice");
    }

    @Test
    void unauthenticatedRequestIsKeyedByClientIp() {
        ClientKey key = ClientKey.of(RiskTestContexts.anonymous());

        assertThat(key).isEqualTo(new ClientKey(ClientKey.Kind.IP, RiskTestContexts.CLIENT_IP));
        assertThat(key.asString()).isEqualTo("ip:" + RiskTestContexts.CLIENT_IP);
    }

    @Test
    void userAndIpWithSameValueAreDifferentKeys() {
        assertThat(new ClientKey(ClientKey.Kind.USER, "x")).isNotEqualTo(new ClientKey(ClientKey.Kind.IP, "x"));
    }

    @Test
    void rejectsNullOrBlank() {
        assertThatThrownBy(() -> new ClientKey(null, "x")).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new ClientKey(ClientKey.Kind.USER, " ")).isInstanceOf(IllegalArgumentException.class);
    }
}
