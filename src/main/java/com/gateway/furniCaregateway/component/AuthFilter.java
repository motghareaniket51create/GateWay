
package com.gateway.furniCaregateway.component;


import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(authentication -> {
                    JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;

                    String username = jwtToken.getToken().getClaimAsString("preferred_username");
                    String email = jwtToken.getToken().getClaimAsString("email");

                    // Forward user info as headers to home service
                    ServerWebExchange modifiedExchange = exchange.mutate()
                            .request(r -> r.header("X-User-Name", username)
                                    .header("X-User-Email", email))
                            .build();

                    return chain.filter(modifiedExchange);
                });
    }

    @Override
    public int getOrder() {
        return -1; // run this filter first
    }
}