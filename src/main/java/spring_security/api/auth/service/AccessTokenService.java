package spring_security.api.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AccessTokenService {

    private static final Set<String> DEFAULT_SCOPES = Set.of("read", "write", "photo", "openid", "profile");
    private static final long ACCESS_TOKEN_TTL_SECONDS = 3600L;

    private final JwtEncoder jwtEncoder;
    private final AuthorizationServerSettings authorizationServerSettings;

    public Map<String, Object> issueAccessToken(Authentication authentication, String userId) {
        String username = resolveUsername(authentication, userId);
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(ACCESS_TOKEN_TTL_SECONDS, ChronoUnit.SECONDS);
        String scope = DEFAULT_SCOPES.stream().sorted().collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(authorizationServerSettings.getIssuer())
                .subject(username)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim("scope", scope)
                .claim("preferred_username", username)
                .build();

        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("access_token", jwt.getTokenValue());
        result.put("token_type", "Bearer");
        result.put("expires_in", ACCESS_TOKEN_TTL_SECONDS);
        result.put("scope", scope);
        return result;
    }

    private String resolveUsername(Authentication authentication, String userId) {
        if (authentication != null && StringUtils.hasText(authentication.getName())) {
            return authentication.getName();
        }
        if (StringUtils.hasText(userId)) {
            return userId;
        }
        throw new IllegalArgumentException("Cannot determine username for access token");
    }
}
