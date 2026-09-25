package com.apishield.risk.context;

import com.apishield.context.RequestContext;
import reactor.core.publisher.Mono;

/**
 * Supplies one type of {@link ContextualInput} for a request, before scoring. This - not the risk
 * engine - is where any I/O belongs (configuration lookups today; Redis/PostgreSQL later), so the
 * engine itself stays pure and synchronous.
 * <p>
 * Implementations must be non-blocking. Return an empty {@code Mono} when there is simply no data for
 * the request. Errors and slow responses need no handling here: {@link ContextualInputCollector}
 * applies a timeout and turns any failure into a missing input on a degraded context, so a provider
 * can never block or fail a request.
 * <p>
 * Registered automatically as Spring beans; at most one provider per input type.
 */
public interface ContextualInputProvider<T extends ContextualInput> {

    Class<T> type();

    Mono<T> provide(RequestContext request);
}
