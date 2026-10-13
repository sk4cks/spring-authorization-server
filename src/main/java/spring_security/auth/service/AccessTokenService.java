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
import spring_security.common.exception.ApiException;
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
 * 로그인 성공 후 access/refresh JWT 발급.
 * 아이디/비밀번호 로그인과 SNS 가입 직후 사용.
 * JWT {@code sub}는 {@code userId}, {@code email}은 {@code SYS_USER.MAIL_ADDRESS}.
 */
@Service
@RequiredArgsConstructor
public class AccessTokenService {

    /** AppConfig RegisteredClient.clientId 와 같은 값. */
    private static final String SPA_CLIENT_ID = "react-note";
    /** JWT scope 클레임 + OAuth2Authorization.authorizedScopes. */
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
     * 인증된 userId로 SYS_USER 조회 뒤 {@link #issueAccessTokenForUser(SysUser)} 로 위임.
     */
    public Map<String, Object> issueAccessToken(Authentication authentication, String userId) {
        // 토큰을 어떤 클라이언트로 발급할지 확인. 없으면 설정 누락.
        RegisteredClient client = clientRepository.findByClientId(SPA_CLIENT_ID);
        if (client == null) {
            throw new IllegalStateException("SPA client not configured: " + SPA_CLIENT_ID);
        }

        // Authentication.name(로그인 id)을 우선하고, 없으면 요청 body의 userId 사용.
        String username = resolveUsername(authentication, userId);

        // 탈퇴하지 않은 SYS_USER만. 없으면 로그인 성공 직후라도 발급 생략.
        SysUser user = sysUserQueryRepository.findByUserId(username)
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND, "User not found: " + username));

        // refresh grant에 쓸 Principal은 방금 인증된 Authentication을 그대로 전달.
        return issueAccessTokenForUser(user, authentication);
    }

    /** SYS_USER 가 이미 존재할 때 토큰만 발급 (SNS 온보딩 완료 등). */
    public Map<String, Object> issueAccessTokenForUser(SysUser user) {
        // SNS 온보딩은 SecurityContext Authentication이 없어서 Principal placeholder 생성.
        return issueAccessTokenForUser(user, null);
    }

    /**
     * JWT와 refresh_token 생성 후, 나중에 갱신할 수 있게 저장.
     */
    private Map<String, Object> issueAccessTokenForUser(SysUser user, Authentication authentication) {
        // issueAccessToken에서도 조회하지만, SNS 경로는 여기만 타므로 한 번 더 확인.
        RegisteredClient client = clientRepository.findByClientId(SPA_CLIENT_ID);
        if (client == null) {
            throw new IllegalStateException("SPA client not configured: " + SPA_CLIENT_ID);
        }

        // JWT sub / preferred_username / OAuth2Authorization.principalName.
        String username = user.getUserId();
        Instant issuedAt = Instant.now();

        // access는 1시간, refresh는 30일. TokenSettings와 맞춤.
        Instant accessExpiresAt = issuedAt.plus(ACCESS_TOKEN_TTL_SECONDS, ChronoUnit.SECONDS);
        Instant refreshExpiresAt = issuedAt.plus(REFRESH_TOKEN_TTL_DAYS, ChronoUnit.DAYS);

        // 순서를 고정하려고 LinkedHashSet. scope 문자열은 정렬해서 추가.
        Set<String> scopes = new LinkedHashSet<>(DEFAULT_SCOPES);
        String scope = scopes.stream().sorted().collect(Collectors.joining(" "));

        // issuer, sub(userId), email, scope를 JWT에 추가.
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(authorizationServerSettings.getIssuer())
                .subject(username)
                .issuedAt(issuedAt)
                .expiresAt(accessExpiresAt)
                .claim("scope", scope)
                .claim("preferred_username", username)
                .claim("email", user.getMailAddress())
                .build();

        // AppConfig JWK(RSA)로 서명. BFF Resource Server가 같은 issuer로 검증.
        Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims));

        // SAS가 refresh 때 꺼내 쓸 access 토큰 객체. 값은 JWT 문자열.
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(),
                issuedAt,
                accessExpiresAt,
                scopes);

        // opaque refresh. JWT가 아니라 UUID라서 서버에 저장해야 이후 갱신 가능.
        OAuth2RefreshToken refreshToken =
                new OAuth2RefreshToken(UUID.randomUUID().toString(), issuedAt, refreshExpiresAt);

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .id(UUID.randomUUID().toString())
                .principalName(username)
                // 로컬 로그인도 authorization_code grant로 저장. SAS refresh가 이 타입을 기대.
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

        // JSON 키 순서를 고정하려고 LinkedHashMap.
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
        // DaoAuthenticationProvider가 넣은 name = SYS_USER.USER_ID.
        if (authentication != null && StringUtils.hasText(authentication.getName())) {
            return authentication.getName();
        }

        // authenticate 직후인데 name이 비는 경우는 거의 없고, body userId로 폴백.
        if (StringUtils.hasText(userId)) {
            return userId;
        }

        throw new IllegalArgumentException("Cannot determine username for access token");
    }

    /**
     * OAuth2Authorization Principal attribute.
     * SNS 온보딩처럼 SecurityContext Authentication 이 없으면 userId 로 placeholder 생성.
     * (refresh_token grant 가 {@code authorization.getAttribute(Principal)} 을 사용)
     */
    private static Authentication principalFor(Authentication authentication, String username) {
        // 로컬 로그인은 검증된 Authentication을 그대로 유지.
        if (authentication != null) {
            return authentication;
        }

        // SNS 온보딩은 비밀번호가 없음. credentials는 쓰지 않으니 placeholder.
        return new UsernamePasswordAuthenticationToken(username, "N/A");
    }
}
