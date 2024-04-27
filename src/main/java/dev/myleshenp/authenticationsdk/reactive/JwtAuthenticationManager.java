package dev.myleshenp.authenticationsdk.reactive;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import reactor.core.publisher.Mono;

public class JwtAuthenticationManager implements ReactiveAuthenticationManager {


    private final String jwtUri;
    private final NimbusJwtDecoder decoder;

    public JwtAuthenticationManager(String jwtUri) {
        this.jwtUri = jwtUri;
        this.decoder = NimbusJwtDecoder.withIssuerLocation(jwtUri).build();
    }



    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        // This gives me the authentication token, so when this token is created i need to have all the extractions done
//        return Mono.just(new PreAuthenticatedAuthenticationToken(l));
        return null;
    }
}
