package com.apishield.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;

/**
 * Replaces Spring Boot's default WebFlux security chain (which would otherwise require HTTP Basic
 * login with a generated password, or apply its own resource-server chain in front of the gateway).
 * <p>
 * Authentication of gateway traffic is performed by {@link JwtAuthenticationFilter} inside the
 * gateway filter chain, after the RequestContext is created - so this WebFilter-level chain is
 * deliberately a stateless pass-through: no sessions, no CSRF (bearer-token API, no cookies), no
 * login mechanisms, and no response-header rewriting of proxied downstream responses.
 */
@Configuration(proxyBeanMethods = false)
public class WebFluxSecurityConfig {

    @Bean
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
