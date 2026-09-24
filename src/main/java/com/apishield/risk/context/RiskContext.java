package com.apishield.risk.context;

import com.apishield.context.RequestContext;

import java.util.Objects;

/**
 * Everything the risk engine may consider besides the threat signals themselves: the request's
 * {@link RequestContext} (userId, clientIp, route, method, path, timestamp) and any
 * {@link ContextualInputs} gathered for it beforehand.
 */
public record RiskContext(RequestContext request, ContextualInputs inputs) {

    public RiskContext {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(inputs, "inputs");
    }

    /** A risk context for a request with no additional contextual inputs. */
    public static RiskContext withoutInputs(RequestContext request) {
        return new RiskContext(request, ContextualInputs.empty());
    }
}
