package com.apishield.risk;

import com.apishield.context.RequestContext;
import com.apishield.context.RouteInfo;
import com.apishield.risk.context.ContextualInputs;
import com.apishield.risk.context.RiskContext;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/** Test fixtures for risk-engine tests. */
public final class RiskTestContexts {

    public static final String ROUTE_ID = "user-service";
    public static final String CLIENT_IP = "10.0.0.5";
    private static final Instant TIMESTAMP = Instant.parse("2026-01-01T00:00:00Z");

    private RiskTestContexts() {
    }

    public static RequestContext request(String userId, String routeId) {
        return new RequestContext("req-1", "GET", "/api/users/1", Map.of(), Map.of(), CLIENT_IP, TIMESTAMP,
                Optional.ofNullable(routeId).map(id -> new RouteInfo(id, URI.create("http://localhost:8081"))),
                Optional.ofNullable(userId));
    }

    public static RequestContext authenticated(String userId) {
        return request(userId, ROUTE_ID);
    }

    public static RequestContext anonymous() {
        return request(null, ROUTE_ID);
    }

    public static RiskContext context(RequestContext request, ContextualInputs inputs) {
        return new RiskContext(request, inputs);
    }

    public static RiskContext withoutInputs(RequestContext request) {
        return RiskContext.withoutInputs(request);
    }
}
