package spring_security.api.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AccessTokenService {

    private static final String SPA_CLIENT_ID = "react-note";
    private static final Set<String> DEFAULT_SCOPES =
            Set.of("read", "write", "photo", "openid", "profile");
    private static final long ACCESS_TOKEN_TTL_SECONDS = 3600L;
    private static final long REFRESH_TOKEN_TTL_DAYS = 30L;

    private final JwtEncoder jwtEncoder;
    private final AuthorizationServerSettings authorizationServerSettings;
    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;

    public Map<String, Object> issueAccessToken(Authentication authentication, String userId) {
        RegisteredClient client = clientRepository.findByClientId(SPA_CLIENT_ID);
        if (client == null) {
            throw new IllegalStateException("SPA client not configured: " + SPA_CLIENT_ID);
        }

        String username = resolveUsername(authentication, userId);
        Instant issuedAt = Instant.now();
        Instant accessExpiresAt = issuedAt.plus(ACCESS_TOKEN_TTL_SECONDS, ChronoUnit.SECONDS);
        Instant refreshExpiresAt = issuedAt.plus(REFRESH_TOKEN_TTL_DAYS, ChronoUnit.DAYS);
        Set<String> scopes = new LinkedHashSet<>(DEFAULT_SCOPES);
        String scope = scopes.stream().sorted().collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(authorizationServerSettings.getIssuer())
                .subject(username)
                .issuedAt(issuedAt)
                .expiresAt(accessExpiresAt)
                .claim("scope", scope)
                .claim("preferred_username", username)
                .build();

        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(),
                issuedAt,
                accessExpiresAt,
                scopes);

        OAuth2RefreshToken refreshToken =
                new OAuth2RefreshToken(UUID.randomUUID().toString(), issuedAt, refreshExpiresAt);

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .id(UUID.randomUUID().toString())
                .principalName(username)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(scopes)
                .attribute(Principal.class.getName(), authentication)
                .token(accessToken, metadata -> metadata.put(
                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()))
                .refreshToken(refreshToken)
                .build();

        authorizationService.save(authorization);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("access_token", jwt.getTokenValue());
        result.put("token_type", "Bearer");
        result.put("expires_in", ACCESS_TOKEN_TTL_SECONDS);
        result.put("refresh_token", refreshToken.getTokenValue());
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
