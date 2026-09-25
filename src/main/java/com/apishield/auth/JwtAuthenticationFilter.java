package com.apishield.auth;

import com.apishield.context.RequestContext;
import com.apishield.context.RequestContextAttributes;
import com.apishield.context.RequestContextFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Authenticates every routed request with an {@code Authorization: Bearer <JWT>} header and
 * attaches the authenticated identity (the JWT {@code sub} claim) to the request's
 * {@link RequestContext}. Runs between {@link RequestContextFilter} and
 * {@link com.apishield.security.SecurityGatewayFilter}, so only authenticated requests reach
 * threat analysis, and a RequestContext exists even for requests rejected here.
 * <p>
 * This is a gateway {@link GlobalFilter} rather than Spring Security's {@code oauth2ResourceServer()}
 * {@code WebFilter} because WebFilters run before gateway route matching - i.e. before the
 * RequestContext exists. The validation itself is still entirely Spring Security's: bearer token
 * extraction ({@link ServerBearerTokenAuthenticationConverter}), JWT decoding/signature/timestamp
 * validation ({@link JwtReactiveAuthenticationManager} over the configured {@link ReactiveJwtDecoder}),
 * and RFC 6750 error responses ({@link BearerTokenServerAuthenticationEntryPoint}).
 * <p>
 * Behavior:
 * <ul>
 *   <li>Valid JWT with a {@code sub} claim: RequestContext replaced with a copy carrying
 *       {@code userId}, authentication published to {@link ReactiveSecurityContextHolder}, chain continues.</li>
 *   <li>Missing token (no Authorization header, or a non-Bearer scheme): 401,
 *       {@code WWW-Authenticate: Bearer}.</li>
 *   <li>Malformed header/JWT, expired JWT, invalid signature, or no {@code sub} claim: 401,
 *       {@code WWW-Authenticate: Bearer error="invalid_token"}.</li>
 *   <li>No decoder configured: no token can be validated, so the two cases above apply - 401
 *       {@code Bearer} without a token, 401 {@code Bearer error="invalid_token"} with one.</li>
 *   <li>Server-side failure of a configured decoder (e.g. JWK set unreachable): the error propagates
 *       and the request is never routed - fail closed, but not misreported as a client credential problem.</li>
 * </ul>
 * In every non-authenticated case the chain is not invoked, so the request is never routed.
 * Tokens are never logged and never stored: the RequestContext excludes the Authorization header
 * by construction, and only the {@code sub} claim is copied into it.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    public static final int ORDER = RequestContextFilter.ORDER + 1;

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /**
     * Used when no decoder is configured: no bearer token can be validated, so every one is rejected
     * as an invalid token (401). The description is deliberately generic - it must not reveal the
     * server's configuration to clients.
     */
    private static final ReactiveAuthenticationManager REJECT_ALL_TOKENS = authentication ->
            Mono.error(new InvalidBearerTokenException("The bearer token could not be validated"));

    private final ServerAuthenticationConverter bearerTokenConverter = new ServerBearerTokenAuthenticationConverter();
    private final ServerAuthenticationEntryPoint entryPoint = new BearerTokenServerAuthenticationEntryPoint();
    private final ReactiveAuthenticationManager authenticationManager;

    /**
     * The decoder is Spring Boot's auto-configured one (see application.yml for the properties that
     * create it). Optional so the application still starts without one - see {@link #REJECT_ALL_TOKENS}.
     */
    @Autowired
    public JwtAuthenticationFilter(ObjectProvider<ReactiveJwtDecoder> jwtDecoder) {
        this(jwtDecoder.getIfAvailable());
    }

    public JwtAuthenticationFilter(ReactiveJwtDecoder jwtDecoder) {
        if (jwtDecoder == null) {
            log.warn("No JWT decoder configured (spring.security.oauth2.resourceserver.jwt.*) - "
                    + "every routed request will be rejected with 401 until one is configured");
            this.authenticationManager = REJECT_ALL_TOKENS;
        } else {
            this.authenticationManager = new JwtReactiveAuthenticationManager(jwtDecoder);
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return authenticate(exchange)
                .onErrorResume(JwtAuthenticationFilter::isClientAuthenticationFailure,
                        ex -> reject(exchange, (AuthenticationException) ex))
                .flatMap(authentication -> proceedAuthenticated(exchange, chain, authentication));
    }

    private Mono<JwtAuthenticationToken> authenticate(ServerWebExchange exchange) {
        return bearerTokenConverter.convert(exchange)
                .switchIfEmpty(Mono.error(() -> new AuthenticationCredentialsNotFoundException("Bearer token is missing")))
                .flatMap(authenticationManager::authenticate)
                .cast(JwtAuthenticationToken.class)
                .filter(authentication -> hasText(authentication.getToken().getSubject()))
                .switchIfEmpty(Mono.error(() -> new InvalidBearerTokenException("JWT has no 'sub' claim")));
    }

    private Mono<Void> proceedAuthenticated(ServerWebExchange exchange, GatewayFilterChain chain,
                                            JwtAuthenticationToken authentication) {
        RequestContext authenticated = RequestContextAttributes.require(exchange)
                .withUserId(authentication.getToken().getSubject());
        RequestContextAttributes.put(exchange, authenticated);
        return chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
    }

    private Mono<JwtAuthenticationToken> reject(ServerWebExchange exchange, AuthenticationException ex) {
        if (log.isDebugEnabled()) {
            log.debug("Authentication rejected for request {}: {}", exchange.getRequest().getId(), failureReason(ex));
        }
        return entryPoint.commence(exchange, ex).then(Mono.empty());
    }

    /**
     * Client credential problems get a 401. {@link AuthenticationServiceException} (decoder missing
     * or JWK set unreachable) is a server-side fault and is deliberately excluded.
     */
    private static boolean isClientAuthenticationFailure(Throwable ex) {
        return ex instanceof AuthenticationException && !(ex instanceof AuthenticationServiceException);
    }

    /**
     * Logs only an error code or exception type - never the exception message, which for JWT parse
     * failures could conceivably echo token content.
     */
    private static String failureReason(AuthenticationException ex) {
        return ex instanceof OAuth2AuthenticationException oauth2
                ? oauth2.getError().getErrorCode()
                : ex.getClass().getSimpleName();
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
