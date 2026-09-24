package com.apishield.event.api;

import com.apishield.event.SecurityEvent;
import com.apishield.event.SecurityEventRepository;
import com.apishield.model.Decision;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Read-only access to persisted security events for the dashboard.
 * <p>
 * Served by APIShield itself, not proxied through a gateway route, so it does not pass through the
 * gateway filters (and dashboard reads are not themselves recorded as security events). It is
 * protected by JWT authentication in {@link com.apishield.auth.WebFluxSecurityConfig} instead.
 * <ul>
 *   <li>{@code GET /api/security/events?page=0&size=20&decision=BLOCK} - newest first; {@code page}
 *       is zero-based, {@code size} is 1..{@value #MAX_PAGE_SIZE}, {@code decision} is optional and
 *       must be a decision outcome name (e.g. {@code ALLOW}, {@code BLOCK}).</li>
 *   <li>{@code GET /api/security/events/{id}} - one event, 404 if unknown.</li>
 * </ul>
 */
@RestController
@RequestMapping(SecurityEventController.BASE_PATH)
public class SecurityEventController {

    public static final String BASE_PATH = "/api/security/events";
    public static final int DEFAULT_PAGE_SIZE = 20;
    public static final int MAX_PAGE_SIZE = 100;

    private final SecurityEventRepository repository;

    public SecurityEventController(SecurityEventRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public Mono<SecurityEventPageResponse> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "" + DEFAULT_PAGE_SIZE) int size,
            @RequestParam(required = false) Decision.Outcome decision) {
        if (page < 0) {
            return Mono.error(badRequest("page must be >= 0"));
        }
        if (size < 1 || size > MAX_PAGE_SIZE) {
            return Mono.error(badRequest("size must be between 1 and " + MAX_PAGE_SIZE));
        }

        Pageable pageable = PageRequest.of(page, size);
        Flux<SecurityEvent> events = decision == null
                ? repository.findAllByOrderByOccurredAtDescIdDesc(pageable)
                : repository.findByDecisionOrderByOccurredAtDescIdDesc(decision.name(), pageable);
        Mono<Long> total = decision == null
                ? repository.count()
                : repository.countByDecision(decision.name());

        return Mono.zip(events.map(SecurityEventResponse::from).collectList(), total)
                .map(result -> SecurityEventPageResponse.of(result.getT1(), page, size, result.getT2()));
    }

    @GetMapping("/{id}")
    public Mono<SecurityEventResponse> get(@PathVariable UUID id) {
        return repository.findById(id)
                .map(SecurityEventResponse::from)
                .switchIfEmpty(Mono.error(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "security event not found")));
    }

    private static ResponseStatusException badRequest(String reason) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, reason);
    }
}
