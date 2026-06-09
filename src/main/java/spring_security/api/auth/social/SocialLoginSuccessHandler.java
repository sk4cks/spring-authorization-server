package spring_security.api.auth.social;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
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

@Component
@RequiredArgsConstructor
public class SocialLoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final String SPA_CLIENT_ID = "react-note";

    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;
    private final SavedRequestAwareAuthenticationSuccessHandler savedRequestHandler =
            new SavedRequestAwareAuthenticationSuccessHandler();

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        HttpSession session = request.getSession(false);
        if (session == null) {
            savedRequestHandler.onAuthenticationSuccess(request, response, authentication);
            return;
        }

        String state = (String) session.getAttribute(SocialLoginAttributes.STATE);
        String codeChallenge = (String) session.getAttribute(SocialLoginAttributes.CODE_CHALLENGE);
        String redirectUri = (String) session.getAttribute(SocialLoginAttributes.REDIRECT_URI);

        if (!StringUtils.hasText(state) || !StringUtils.hasText(codeChallenge) || !StringUtils.hasText(redirectUri)) {
            savedRequestHandler.onAuthenticationSuccess(request, response, authentication);
            return;
        }

        session.removeAttribute(SocialLoginAttributes.STATE);
        session.removeAttribute(SocialLoginAttributes.CODE_CHALLENGE);
        session.removeAttribute(SocialLoginAttributes.REDIRECT_URI);

        RegisteredClient client = clientRepository.findByClientId(SPA_CLIENT_ID);
        if (client == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "SPA client not configured");
            return;
        }

        String principalName = resolvePrincipalName(authentication);
        String code = UUID.randomUUID().toString();
        Instant now = Instant.now();

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

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName(principalName)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(client.getScopes())
                .attribute(Principal.class.getName(), authentication)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                .token(new OAuth2AuthorizationCode(code, now, now.plus(Duration.ofMinutes(5))))
                .build();

        authorizationService.save(authorization);

        String target = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam(OAuth2ParameterNames.CODE, code)
                .queryParam(OAuth2ParameterNames.STATE, state)
                .build()
                .encode(StandardCharsets.UTF_8)
                .toUriString();

        response.sendRedirect(target);
    }

    private String resolvePrincipalName(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcUser oidcUser && StringUtils.hasText(oidcUser.getEmail())) {
            return oidcUser.getEmail();
        }
        if (principal instanceof OAuth2User oauth2User) {
            String provider = oauth2User.getAttribute("provider") instanceof String p ? p : "";

            if ("naver".equals(provider)) {
                String email = asNonBlankString(oauth2User.getAttribute("email"));
                if (email != null) {
                    return email;
                }
            }
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
}
