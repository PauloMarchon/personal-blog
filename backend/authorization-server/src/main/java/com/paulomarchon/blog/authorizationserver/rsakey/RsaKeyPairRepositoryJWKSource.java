package com.paulomarchon.blog.authorizationserver.rsakey;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class RsaKeyPairRepositoryJWKSource implements JWKSource<SecurityContext>, OAuth2TokenCustomizer<JwtEncodingContext> {
    private final RsaKeyPairRepository keyPairRepository;

    public RsaKeyPairRepositoryJWKSource(RsaKeyPairRepository keyPairRepository) {
        this.keyPairRepository = keyPairRepository;
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
        List<RsaKeyPair> keyPairs = this.keyPairRepository.findKeyPairs();
        List<JWK> result = new ArrayList<>(keyPairs.size());

        for (RsaKeyPair keyPair : keyPairs) {
            RSAKey rsaKey = new RSAKey.Builder(keyPair.getPublicKey())
                    .privateKey(keyPair.getPrivateKey())
                    .keyID(keyPair.getId())
                    .build();
            if (jwkSelector.getMatcher().matches(rsaKey))
                result.add(rsaKey);
        }
        return result;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();
        JwsHeader.Builder headers = context.getJwsHeader();
        JwtClaimsSet.Builder claims = context.getClaims();

        if(OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toSet());
            claims.claim("role", authorities);
        }

        List<RsaKeyPair> keyPairs = this.keyPairRepository.findKeyPairs();
        String kid = keyPairs.getFirst().getId();
        context.getJwsHeader().keyId(kid);
    }
}
