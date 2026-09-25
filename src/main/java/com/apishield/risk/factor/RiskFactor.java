package com.apishield.risk.factor;

import com.apishield.model.RiskAdjustment;
import com.apishield.risk.context.RiskContext;

/**
 * One contextual influence on a request's risk. Pure and synchronous: reads only the
 * {@link RiskContext} (the RequestContext plus inputs already gathered by providers) and never performs
 * I/O, reads a clock, or uses Reactor. Registered automatically as Spring beans.
 * <p>
 * Must return exactly one {@link RiskAdjustment}; when its data is absent it must return
 * {@link RiskAdjustment#missing} (multiplier 1.0, prior 0.0).
 */
public interface RiskFactor {

    /** Unique, stable name - also the order factors are applied in, for deterministic results. */
    String name();

    RiskAdjustment assess(RiskContext context);
}
