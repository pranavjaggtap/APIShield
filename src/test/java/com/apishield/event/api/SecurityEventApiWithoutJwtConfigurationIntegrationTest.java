package com.apishield.event.api;

import com.apishield.auth.TestJwts;
import com.apishield.event.SecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.mockito.Mockito.verifyNoInteractions;

/**
 * With no JWT issuer/JWK/public key configured (the repository's default), the dashboard API must fail
 * closed - no token, whatever it looks like, can be accepted.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class SecurityEventApiWithoutJwtConfigurationIntegrationTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private SecurityEventRepository repository;

    @Test
    void everyRequestIsRejected() {
        webTestClient.get().uri("/api/security/events")
                .exchange()
                .expectStatus().isUnauthorized();
        webTestClient.get().uri("/api/security/events")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestJwts.validToken("analyst-1"))
                .exchange()
                .expectStatus().isUnauthorized();

        verifyNoInteractions(repository);
    }
}
