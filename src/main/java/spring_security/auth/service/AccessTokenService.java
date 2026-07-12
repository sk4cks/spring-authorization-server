package spring_security.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
import spring_security.user.domain.SysUser;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;
import spring_security.user.repository.SysUserQueryRepository;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * SPA(react-note)용 access/refresh 토큰 발급.
 * <p>
 * 로컬 로그인({@code POST /auth/login})과 SNS 온보딩 완료({@code POST /auth/social/register})에서 사용한다.
 * SNS authorization_code 교환({@code POST /oauth2/token})은 Spring Authorization Server 기본 플로우이며,
 * JWT 클레임 보강은 {@link spring_security.config.AuthorizationServerConfig#jwtCustomizer()} 가 담당한다.
 * <p>
 * JWT {@code sub} = 내부 {@code userId}, {@code email} = {@code SYS_USER.MAIL_ADDRESS}.
 * refresh_token 은 {@link OAuth2AuthorizationService}에 저장되어 이후 갱신에 쓰인다.
 */
@Service
@RequiredArgsConstructor
public class AccessTokenService {

    private static final String SPA_CLIENT_ID = "react-note";
    private static final Set<String> DEFAULT_SCOPES =
            Set.of("read", "write", "openid", "profile");
    private static final long ACCESS_TOKEN_TTL_SECONDS = 3600L;
    private static final long REFRESH_TOKEN_TTL_DAYS = 30L;

    private final JwtEncoder jwtEncoder;
    private final AuthorizationServerSettings authorizationServerSettings;
    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;
    private final SysUserQueryRepository sysUserQueryRepository;

    /**
     * 로컬 계정 로그인 성공 후 토큰 발급.
     * 인증된 userId로 SYS_USER 를 조회한 뒤 {@link #issueAccessTokenForUser(SysUser)} 로 위임한다.
     */
    public Map<String, Object> issueAccessToken(Authentication authentication, String userId) {
        RegisteredClient client = clientRepository.findByClientId(SPA_CLIENT_ID);
        if (client == null) {
            throw new IllegalStateException("SPA client not configured: " + SPA_CLIENT_ID);
        }

        String username = resolveUsername(authentication, userId);
        SysUser user = sysUserQueryRepository.findByUserId(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND, "User not found: " + username));

        return issueAccessTokenForUser(user, authentication);
    }

    /** SYS_USER 가 이미 존재할 때 토큰만 발급 (SNS 온보딩 완료 등). */
    public Map<String, Object> issueAccessTokenForUser(SysUser user) {
        return issueAccessTokenForUser(user, null);
    }

    /**
     * JWT + refresh_token 생성 및 OAuth2Authorization 저장.
     * BFF 응답 형식(OAuth2 token endpoint 호환)으로 반환한다.
     */
    private Map<String, Object> issueAccessTokenForUser(SysUser user, Authentication authentication) {
        RegisteredClient client = clientRepository.findByClientId(SPA_CLIENT_ID);
        if (client == null) {
            throw new IllegalStateException("SPA client not configured: " + SPA_CLIENT_ID);
        }

        String username = user.getUserId();
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
                .claim("email", user.getMailAddress())
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
                // refresh grant 가 tokenContext.principal 로 이 attribute 를 씀 — null 불가
                .attribute(Principal.class.getName(), principalFor(authentication, username))
                .token(accessToken, metadata -> metadata.put(
                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()))
                .refreshToken(refreshToken)
                .build();

        // SAS refresh grant 가 이 authorization 을 조회할 수 있도록 저장
        authorizationService.save(authorization);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("access_token", jwt.getTokenValue());
        result.put("token_type", "Bearer");
        result.put("expires_in", ACCESS_TOKEN_TTL_SECONDS);
        result.put("refresh_token", refreshToken.getTokenValue());
        result.put("scope", scope);
        result.put("mailAddress", user.getMailAddress());
        return result;
    }

    /** Authentication.name 우선, 없으면 요청의 userId (로컬 로그인 폼 기준). */
    private String resolveUsername(Authentication authentication, String userId) {
        if (authentication != null && StringUtils.hasText(authentication.getName())) {
            return authentication.getName();
        }
        if (StringUtils.hasText(userId)) {
            return userId;
        }
        throw new IllegalArgumentException("Cannot determine username for access token");
    }

    /**
     * OAuth2Authorization Principal attribute.
     * SNS 온보딩처럼 SecurityContext Authentication 이 없으면 userId 로 placeholder 를 만든다.
     * (refresh_token grant 가 {@code authorization.getAttribute(Principal)} 을 사용)
     */
    private static Authentication principalFor(Authentication authentication, String username) {
        if (authentication != null) {
            return authentication;
        }
        return new UsernamePasswordAuthenticationToken(username, "N/A");
    }
}
