package com.apishield.context;

import java.net.URI;
import java.util.Objects;

/**
 * The Spring Cloud Gateway route a request matched: its configured id (e.g. {@code user-service})
 * and the downstream service URI it forwards to.
 */
public record RouteInfo(String routeId, URI targetUri) {

    public RouteInfo {
        Objects.requireNonNull(routeId, "routeId");
        Objects.requireNonNull(targetUri, "targetUri");
    }
}
