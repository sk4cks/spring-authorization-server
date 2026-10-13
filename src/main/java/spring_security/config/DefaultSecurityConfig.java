package spring_security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import spring_security.auth.service.CustomUserDetailsService;
import spring_security.auth.oauth.OAuthLoginSuccessHandler;

/**
 * 앱 기본 SecurityFilterChain (Order 2).
 * SAS 체인(Order HIGHEST)이 /oauth2/** 를 먼저 가져가고, 나머지는 이 체인.
 */
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class DefaultSecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;
    private final OAuthLoginSuccessHandler oauthLoginSuccessHandler;
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;
    private final OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;
    private final OAuth2AuthorizationRequestResolver authorizationRequestResolver;

    /** 로컬 로그인용 인증. SNS 계정은 passwordHash가 없어서 이 경로 제외. */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        // 로컬 로그인만. SNS 계정은 passwordHash가 없어서 이 경로 제외.
        provider.setUserDetailsService(customUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());

        return provider;
    }

    /** 앱 기본 필터 체인. SAS가 가져가지 않은 경로. */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                // SNS prepare가 세션에 PKCE를 넣으므로 STATELESS가 아님.
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(request -> request
                        // /auth/login, /auth/register, SNS prepare, oauth2 시작은 공개.
                        .requestMatchers("/login", "/auth/**", "/oauth2/**", "/error").permitAll()
                        .anyRequest().authenticated())
                // BFF가 JSON POST 하므로 로그인 CSRF는 비활성. form login 페이지는 기본 CSRF.
                .csrf(csrf -> csrf.ignoringRequestMatchers("/auth/**"))
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(endpoint -> endpoint
                                // Google이면 access_type=offline 을 붙이는 resolver.
                                .authorizationRequestResolver(authorizationRequestResolver))
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(oauth2UserService)
                                .oidcUserService(oidcUserService))
                        // SPA PKCE 세션이 있으면 /oauth/callback 으로 code 전달.
                        .successHandler(oauthLoginSuccessHandler))
                // SNS authorize 미인증 시 LoginUrlAuthenticationEntryPoint("/login")이 이 form 사용.
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /** {noop} 테스트 비밀번호 prefix를 지원하는 인코더. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // {noop}1234 등 테스트 비밀번호 prefix 지원
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /** AuthService.login이 UsernamePasswordAuthenticationToken을 검증할 때 쓰는 매니저. */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        // AuthService.login이 이 매니저로 UsernamePasswordAuthenticationToken 검증.
        return config.getAuthenticationManager();
    }
}
