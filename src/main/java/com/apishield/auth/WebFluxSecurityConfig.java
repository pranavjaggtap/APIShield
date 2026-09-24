package com.apishield.auth;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

/**
 * Replaces Spring Boot's default WebFlux security chain (which would otherwise require HTTP Basic
 * login with a generated password, or apply its own resource-server chain in front of the gateway).
 * Two chains, checked in order:
 * <ol>
 *   <li>{@link #securityApiFilterChain} - APIShield's own REST API under {@value #SECURITY_API_PATHS}
 *       (e.g. the security events dashboard API). These endpoints are served by APIShield's own
 *       controllers, which take precedence over gateway routes, so the gateway filters -
 *       including {@link JwtAuthenticationFilter} - never run for them. They are protected here
 *       instead, with Spring Security's standard JWT resource-server support and the same
 *       {@link ReactiveJwtDecoder}. Without a configured decoder every request is denied (401),
 *       mirroring the gateway's fail-closed behavior.</li>
 *   <li>{@link #securityWebFilterChain} - everything else. Authentication of gateway traffic is
 *       performed by {@link JwtAuthenticationFilter} inside the gateway filter chain, after the
 *       RequestContext is created - so this chain is deliberately a stateless pass-through: no
 *       sessions, no CSRF (bearer-token API, no cookies), no login mechanisms, and no
 *       response-header rewriting of proxied downstream responses.</li>
 * </ol>
 */
@Configuration(proxyBeanMethods = false)
public class WebFluxSecurityConfig {

    static final String SECURITY_API_PATHS = "/api/security/**";

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityWebFilterChain securityApiFilterChain(ServerHttpSecurity http,
                                                  ObjectProvider<ReactiveJwtDecoder> jwtDecoder) {
        http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(SECURITY_API_PATHS))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .requestCache(cache -> cache.requestCache(NoOpServerRequestCache.getInstance()))
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new BearerTokenServerAuthenticationEntryPoint()));

        ReactiveJwtDecoder decoder = jwtDecoder.getIfAvailable();
        if (decoder == null) {
            http.authorizeExchange(exchanges -> exchanges.anyExchange().denyAll());
        } else {
            http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                    .oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwt -> jwt.jwtDecoder(decoder)));
        }
        return http.build();
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .headers(ServerHttpSecurity.HeaderSpec::disable)
                .requestCache(cache -> cache.requestCache(NoOpServerRequestCache.getInstance()))
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .build();
    }
}
