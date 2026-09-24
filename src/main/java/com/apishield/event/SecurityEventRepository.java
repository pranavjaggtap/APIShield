package com.apishield.event;

import org.springframework.data.domain.Pageable;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Reactive persistence for {@link SecurityEvent}s. Saving and lookup by id come from
 * {@link R2dbcRepository}. Listing is always newest first, with {@code id} as a tie-breaker so
 * pagination stays stable when events share a timestamp. Pass an unsorted {@link Pageable} - the
 * ordering is part of the query itself.
 */
public interface SecurityEventRepository extends R2dbcRepository<SecurityEvent, UUID> {

    Flux<SecurityEvent> findAllByOrderByOccurredAtDescIdDesc(Pageable pageable);

    Flux<SecurityEvent> findByDecisionOrderByOccurredAtDescIdDesc(String decision, Pageable pageable);

    Mono<Long> countByDecision(String decision);
}
