package com.apishield.event.api;

import com.apishield.event.SecurityEvent;
import com.apishield.event.SecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Controller behavior in isolation (request handling, paging, filtering, DTO mapping). Authentication
 * of these endpoints is covered by SecurityEventApiSecurityIntegrationTest.
 */
class SecurityEventControllerTest {

    private static final UUID NEWER_ID = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID OLDER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    private static final SecurityEvent NEWER_BLOCK = new SecurityEvent(NEWER_ID, "req-2",
            Instant.parse("2026-03-01T10:00:02Z"), "GET", "/api/users/1", "10.0.0.5", "user-42", "user-service",
            "BLOCK", "risk score 0.92 met or exceeded block threshold 0.50", 0.92, 0.92,
            List.of("sql-injection", "xss"), List.of(true, false), List.of(0.9, 0.0),
            List.of("matched: tautology", "no XSS patterns matched"));

    private static final SecurityEvent OLDER_ALLOW = new SecurityEvent(OLDER_ID, "req-1",
            Instant.parse("2026-03-01T10:00:01Z"), "GET", "/api/users/2", "10.0.0.6", null, null,
            "ALLOW", "risk score 0.00 below block threshold 0.50", 0.0, 0.0,
            List.of(), List.of(), List.of(), List.of());

    private final SecurityEventRepository repository = mock(SecurityEventRepository.class);

    private final WebTestClient client =
            WebTestClient.bindToController(new SecurityEventController(repository)).build();

    @Test
    void listReturnsRepositoryOrderNewestFirstWithDefaultPaging() {
        when(repository.findAllByOrderByOccurredAtDescIdDesc(PageRequest.of(0, 20)))
                .thenReturn(Flux.just(NEWER_BLOCK, OLDER_ALLOW));
        when(repository.count()).thenReturn(Mono.just(2L));

        client.get().uri("/api/security/events")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.page").isEqualTo(0)
                .jsonPath("$.size").isEqualTo(20)
                .jsonPath("$.totalElements").isEqualTo(2)
                .jsonPath("$.totalPages").isEqualTo(1)
                .jsonPath("$.content.length()").isEqualTo(2)
                .jsonPath("$.content[0].id").isEqualTo(NEWER_ID.toString())
                .jsonPath("$.content[1].id").isEqualTo(OLDER_ID.toString());
    }

    @Test
    void listMapsEventFieldsIncludingSignals() {
        when(repository.findAllByOrderByOccurredAtDescIdDesc(any())).thenReturn(Flux.just(NEWER_BLOCK));
        when(repository.count()).thenReturn(Mono.just(1L));

        client.get().uri("/api/security/events")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.content[0].requestId").isEqualTo("req-2")
                .jsonPath("$.content[0].timestamp").isEqualTo("2026-03-01T10:00:02Z")
                .jsonPath("$.content[0].method").isEqualTo("GET")
                .jsonPath("$.content[0].path").isEqualTo("/api/users/1")
                .jsonPath("$.content[0].clientIp").isEqualTo("10.0.0.5")
                .jsonPath("$.content[0].userId").isEqualTo("user-42")
                .jsonPath("$.content[0].routeId").isEqualTo("user-service")
                .jsonPath("$.content[0].decision").isEqualTo("BLOCK")
                .jsonPath("$.content[0].riskScore").isEqualTo(0.92)
                .jsonPath("$.content[0].threatScore").isEqualTo(0.92)
                .jsonPath("$.content[0].threatSignals.length()").isEqualTo(2)
                .jsonPath("$.content[0].threatSignals[0].detector").isEqualTo("sql-injection")
                .jsonPath("$.content[0].threatSignals[0].detected").isEqualTo(true)
                .jsonPath("$.content[0].threatSignals[0].severity").isEqualTo(0.9)
                .jsonPath("$.content[0].threatSignals[0].description").isEqualTo("matched: tautology")
                .jsonPath("$.content[0].signalDetectors").doesNotExist();
    }

    @Test
    void listHonorsPageAndSize() {
        when(repository.findAllByOrderByOccurredAtDescIdDesc(PageRequest.of(2, 5))).thenReturn(Flux.empty());
        when(repository.count()).thenReturn(Mono.just(11L));

        client.get().uri("/api/security/events?page=2&size=5")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.page").isEqualTo(2)
                .jsonPath("$.size").isEqualTo(5)
                .jsonPath("$.totalElements").isEqualTo(11)
                .jsonPath("$.totalPages").isEqualTo(3)
                .jsonPath("$.content.length()").isEqualTo(0);
    }

    @Test
    void listFiltersByDecision() {
        when(repository.findByDecisionOrderByOccurredAtDescIdDesc("BLOCK", PageRequest.of(0, 20)))
                .thenReturn(Flux.just(NEWER_BLOCK));
        when(repository.countByDecision("BLOCK")).thenReturn(Mono.just(1L));

        client.get().uri("/api/security/events?decision=BLOCK")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.totalElements").isEqualTo(1)
                .jsonPath("$.content[0].decision").isEqualTo("BLOCK");

        verify(repository, never()).findAllByOrderByOccurredAtDescIdDesc(any());
        verify(repository, never()).count();
    }

    @Test
    void unknownDecisionIsRejected() {
        client.get().uri("/api/security/events?decision=DESTROY")
                .exchange()
                .expectStatus().isBadRequest();

        verify(repository, never()).findByDecisionOrderByOccurredAtDescIdDesc(anyString(), any());
    }

    @Test
    void invalidPagingIsRejected() {
        client.get().uri("/api/security/events?page=-1").exchange().expectStatus().isBadRequest();
        client.get().uri("/api/security/events?size=0").exchange().expectStatus().isBadRequest();
        client.get().uri("/api/security/events?size=101").exchange().expectStatus().isBadRequest();
        client.get().uri("/api/security/events?size=abc").exchange().expectStatus().isBadRequest();

        verify(repository, never()).findAllByOrderByOccurredAtDescIdDesc(any());
    }

    @Test
    void getReturnsSingleEvent() {
        when(repository.findById(eq(NEWER_ID))).thenReturn(Mono.just(NEWER_BLOCK));

        client.get().uri("/api/security/events/{id}", NEWER_ID)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo(NEWER_ID.toString())
                .jsonPath("$.decision").isEqualTo("BLOCK")
                .jsonPath("$.threatSignals[0].detector").isEqualTo("sql-injection");
    }

    @Test
    void getUnknownIdReturns404() {
        UUID unknown = UUID.randomUUID();
        when(repository.findById(eq(unknown))).thenReturn(Mono.empty());

        client.get().uri("/api/security/events/{id}", unknown)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void getMalformedIdReturns400() {
        client.get().uri("/api/security/events/not-a-uuid")
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void decisionFilterAcceptsTheNewFiveTierOutcomes() {
        for (String decision : List.of("MONITOR", "CHALLENGE", "THROTTLE")) {
            when(repository.findByDecisionOrderByOccurredAtDescIdDesc(decision, PageRequest.of(0, 20)))
                    .thenReturn(Flux.empty());
            when(repository.countByDecision(decision)).thenReturn(Mono.just(0L));

            client.get().uri("/api/security/events?decision=" + decision)
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody().jsonPath("$.totalElements").isEqualTo(0);

            verify(repository).findByDecisionOrderByOccurredAtDescIdDesc(decision, PageRequest.of(0, 20));
        }
    }

    @Test
    void noMutationEndpointsExist() {
        client.post().uri("/api/security/events").exchange().expectStatus().isEqualTo(405);
        client.delete().uri("/api/security/events/{id}", NEWER_ID).exchange().expectStatus().isEqualTo(405);
    }
}
