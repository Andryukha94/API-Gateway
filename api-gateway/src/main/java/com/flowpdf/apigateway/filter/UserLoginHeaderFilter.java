package com.flowpdf.apigateway.filter;

import com.flowpdf.apigateway.properties.SecurityProps;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class UserLoginHeaderFilter implements GlobalFilter, Ordered {

    private final SecurityProps props;

    public UserLoginHeaderFilter(SecurityProps props) {
        this.props = props;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .ofType(Authentication.class)
                .map(this::extractJwt)
                .flatMap(jwt -> {
                    if (jwt == null) return chain.filter(exchange);

                    String login = jwt.getClaimAsString(props.userLoginClaim());
                    if (login == null || login.isBlank()) return chain.filter(exchange);

                    ServerWebExchange mutated = exchange.mutate()
                            .request(r -> r.headers(h -> h.set(props.userLoginHeader(), login)))
                            .build();

                    return chain.filter(mutated);
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    private Jwt extractJwt(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jat) {
            return jat.getToken();
        }
        return (auth.getPrincipal() instanceof Jwt jwt) ? jwt : null;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}