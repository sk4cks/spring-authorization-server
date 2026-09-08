package spring_security.auth.oauth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * SNS oauth2Login 성공 후 SPA PKCE 플로우로 연결하는 브릿지.
 * <p>
 * Google/Kakao/Naver 로그인이 끝나면 Spring 기본 success redirect 대신,
 * 프론트가 준비해 둔 PKCE 세션({@link OAuthLoginAttributes#STATE} 등)을 읽어
 * SAS {@link OAuth2Authorization} 에 authorization code 를 저장하고
 * SPA redirect URI({@code /oauth/callback})로 {@code code}&{@code state} 를 넘긴다.
 * <p>
 * 이후 SPA → BFF {@code POST /api/auth/token} → Auth {@code POST /oauth2/token} 으로
 * access_token 이 발급된다. SNS 신원(provider, externalId)은 authorization attribute 에
 * 남겨 두었다가 {@link spring_security.config.AuthorizationServerConfig#jwtCustomizer()} 가
 * JWT {@code sns_*} 클레임으로 옮긴다 (온보딩 userId 선택용).
 */
@Component
@RequiredArgsConstructor
public class OAuthLoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final String SPA_CLIENT_ID = "react-note";

    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;
    private final SavedRequestAwareAuthenticationSuccessHandler savedRequestHandler =
            new SavedRequestAwareAuthenticationSuccessHandler();

    /**
     * PKCE 세션이 없으면 일반 oauth2Login 성공 처리(기본 redirect)로 폴백.
     * SPA 경유 SNS 로그인(/auth/social/prepare)일 때만 아래 브릿지 로직이 동작한다.
     */
    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        // prepare가 세션을 만들었을 때만 false. 없으면 일반 form/oauth 성공으로 보낸다.
        HttpSession session = request.getSession(false);
        if (session == null) {
            savedRequestHandler.onAuthenticationSuccess(request, response, authentication);

            return;
        }

        // SPA가 /auth/social/prepare 때 넣어 둔 PKCE 값.
        String state = (String) session.getAttribute(OAuthLoginAttributes.STATE);
        String codeChallenge = (String) session.getAttribute(OAuthLoginAttributes.CODE_CHALLENGE);
        String redirectUri = (String) session.getAttribute(OAuthLoginAttributes.REDIRECT_URI);

        // 세션은 있는데 PKCE가 없으면 브라우저 직접 oauth2Login이다.
        if (!StringUtils.hasText(state) || !StringUtils.hasText(codeChallenge) || !StringUtils.hasText(redirectUri)) {
            savedRequestHandler.onAuthenticationSuccess(request, response, authentication);

            return;
        }

        // 재사용 방지. code는 아래 authorization에만 남긴다.
        session.removeAttribute(OAuthLoginAttributes.STATE);
        session.removeAttribute(OAuthLoginAttributes.CODE_CHALLENGE);
        session.removeAttribute(OAuthLoginAttributes.REDIRECT_URI);

        RegisteredClient client = clientRepository.findByClientId(SPA_CLIENT_ID);
        if (client == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "SPA client not configured");

            return;
        }

        // JWT sub 후보. 카카오는 숫자 id 대신 nickname/email을 쓴다.
        String principalName = resolvePrincipalName(authentication);

        // SYS_USER 매칭용 — JWT sub(principalName)와 별도로 provider+externalId 보존
        SnsIdentity snsIdentity = resolveSnsIdentity(authentication);

        // SPA가 /oauth2/token에 넘길 authorization_code. 5분 TTL.
        String code = UUID.randomUUID().toString();
        Instant now = Instant.now();

        // SAS token endpoint가 PKCE 검증할 때 이 request의 code_challenge를 본다.
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .clientId(client.getClientId())
                .authorizationUri("social-login")
                .redirectUri(redirectUri)
                .scopes(client.getScopes())
                .state(state)
                .additionalParameters(Map.of(
                        PkceParameterNames.CODE_CHALLENGE, codeChallenge,
                        PkceParameterNames.CODE_CHALLENGE_METHOD, "S256"))
                .build();

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(client)
                .principalName(principalName)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(client.getScopes())
                .attribute(Principal.class.getName(), authentication)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);

        if (snsIdentity != null) {
            // token 교환 시 jwtCustomizer 가 sns_* 클레임으로 복사
            authorizationBuilder
                    .attribute(OAuthLoginAttributes.SNS_PROVIDER, snsIdentity.provider())
                    .attribute(OAuthLoginAttributes.SNS_EXTERNAL_ID, snsIdentity.externalId());
            if (StringUtils.hasText(snsIdentity.externalEmail())) {
                authorizationBuilder.attribute(
                        OAuthLoginAttributes.SNS_EXTERNAL_EMAIL, snsIdentity.externalEmail());
            }
        }

        OAuth2Authorization authorization = authorizationBuilder
                .token(new OAuth2AuthorizationCode(code, now, now.plus(Duration.ofMinutes(5))))
                .build();

        authorizationService.save(authorization);

        // SPA OAuthCallbackView 가 code/state 로 토큰 교환
        String target = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam(OAuth2ParameterNames.CODE, code)
                .queryParam(OAuth2ParameterNames.STATE, state)
                .build()
                .encode(StandardCharsets.UTF_8)
                .toUriString();

        response.sendRedirect(target);
    }

    /**
     * OAuth2Authorization.principalName / JWT sub 후보.
     * provider마다 이메일·닉네임·{@code provider:id} 등 가용한 값을 우선 사용한다.
     */
    private String resolvePrincipalName(Authentication authentication) {
        Object principal = authentication.getPrincipal();

        // Google OIDC는 email이 안정적이다.
        if (principal instanceof OidcUser oidcUser && StringUtils.hasText(oidcUser.getEmail())) {
            return oidcUser.getEmail();
        }

        if (principal instanceof OAuth2User oauth2User) {
            String provider = oauth2User.getAttribute("provider") instanceof String p ? p : "";

            // 네이버는 flatten 후 email이 있으면 그걸 sub로 쓴다.
            if ("naver".equals(provider)) {
                String email = asNonBlankString(oauth2User.getAttribute("email"));
                if (email != null) {
                    return email;
                }
            }

            // 카카오는 이메일이 없을 수 있어서 nickname을 우선한다.
            if ("kakao".equals(provider)) {
                String nickname = asNonBlankString(oauth2User.getAttribute("nickname"));
                if (nickname != null) {
                    return nickname;
                }
            }

            String email = asNonBlankString(oauth2User.getAttribute("email"));
            if (email != null) {
                return email;
            }

            // 이메일도 없으면 provider:id. 온보딩 화면 표시용일 뿐 SYS_USER.USER_ID는 아니다.
            Object id = oauth2User.getAttribute("id");
            if (id != null && StringUtils.hasText(provider)) {
                return provider + ":" + id;
            }
        }

        return authentication.getName();
    }

    private static String asNonBlankString(Object value) {
        if (value instanceof String s && StringUtils.hasText(s)) {
            return s;
        }

        return null;
    }

    /**
     * SYS_USER 의 AUTH_PROVIDER + EXTERNAL_ID 에 대응하는 안정적인 SNS 신원.
     * registrationId(google/kakao/naver)와 provider API 의 id/sub 를 사용한다.
     */
    private SnsIdentity resolveSnsIdentity(Authentication authentication) {
        // oauth2Login 성공이면 이 타입이다. form login이면 SNS 신원이 없다.
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Token)) {
            return null;
        }

        String registrationId = oauth2Token.getAuthorizedClientRegistrationId();
        if (!StringUtils.hasText(registrationId)) {
            return null;
        }

        // SYS_USER.AUTH_PROVIDER enum과 맞추려고 대문자.
        String provider = registrationId.toUpperCase();
        Object principal = authentication.getPrincipal();

        if (principal instanceof OidcUser oidcUser) {
            // Google sub는 계정에 고정된 외부 id.
            String externalId = oidcUser.getSubject();
            String email = asNonBlankString(oidcUser.getEmail());

            return new SnsIdentity(provider, externalId, email);
        }

        if (principal instanceof OAuth2User oauth2User) {
            Object id = oauth2User.getAttribute("id");
            if (id == null) {
                return null;
            }

            String externalEmail = asNonBlankString(oauth2User.getAttribute("email"));

            return new SnsIdentity(provider, id.toString(), externalEmail);
        }

        return null;
    }

    /** {@link OAuthLoginAttributes} attribute 및 온보딩 API 로 전달할 SNS 식별자 묶음 */
    private record SnsIdentity(String provider, String externalId, String externalEmail) {}
}
