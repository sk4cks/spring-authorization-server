package spring_security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import spring_security.auth.oauth.OAuthLoginAttributes;

/**
 * /oauth2/authorize, /oauth2/token, OIDC용 필터 체인.
 * 아이디/비밀번호 로그인은 {@link DefaultSecurityConfig}.
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // 미인증 시 401 대신 로그인 페이지로 redirect (authorize 플로우)
        http.exceptionHandling(exception -> exception
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            // SNS: OAuthLoginSuccessHandler가 저장한 principalName (nickname/email)
            // principal.getName()은 OAuth2User의 id라 카카오 숫자 id가 들어감
            String name = context.getAuthorization().getPrincipalName();
            if (!StringUtils.hasText(name)) {
                name = context.getPrincipal().getName();
            }

            context.getClaims().subject(name);
            context.getClaims().claim("preferred_username", name);

            OAuth2Authorization authorization = context.getAuthorization();
            if (authorization != null) {
                // SNS 로그인 때 저장해 둔 provider/externalId가 있으면 JWT에 넣는다.
                String snsProvider = authorization.getAttribute(OAuthLoginAttributes.SNS_PROVIDER);
                String snsExternalId = authorization.getAttribute(OAuthLoginAttributes.SNS_EXTERNAL_ID);
                if (StringUtils.hasText(snsProvider) && StringUtils.hasText(snsExternalId)) {
                    context.getClaims().claim("sns_provider", snsProvider);
                    context.getClaims().claim("sns_external_id", snsExternalId);

                    String snsEmail = authorization.getAttribute(OAuthLoginAttributes.SNS_EXTERNAL_EMAIL);
                    if (StringUtils.hasText(snsEmail)) {
                        context.getClaims().claim("sns_external_email", snsEmail);
                    }
                }
            }
        };
    }
}
