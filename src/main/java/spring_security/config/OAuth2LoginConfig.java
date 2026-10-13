package spring_security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SNS userInfo 응답 평탄화.
 * Kakao/Naver는 이메일이 중첩 JSON이라 OAuthLoginSuccessHandler가 바로 읽게 펼침.
 */
@Configuration
public class OAuth2LoginConfig {

    /** Kakao/Naver userInfo를 평탄화하는 서비스. */
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

        return userRequest -> {
            OAuth2User user = delegate.loadUser(userRequest);
            String registrationId = userRequest.getClientRegistration().getRegistrationId();

            if ("kakao".equals(registrationId)) {
                // nameAttributeKey=id. 카카오 숫자 id가 Authentication.name.
                return new DefaultOAuth2User(
                        user.getAuthorities(), flattenKakaoAttributes(user.getAttributes()), "id");
            }

            if ("naver".equals(registrationId)) {
                return new DefaultOAuth2User(
                        user.getAuthorities(), flattenNaverAttributes(user.getAttributes()), "id");
            }

            return new DefaultOAuth2User(user.getAuthorities(), user.getAttributes(), "sub");
        };
    }

    /** Kakao: email·nickname은 kakao_account 중첩 — principal/email 조회용 평탄화 */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> flattenKakaoAttributes(Map<String, Object> attributes) {
        Map<String, Object> flat = new LinkedHashMap<>(attributes);
        Object account = attributes.get("kakao_account");
        if (account instanceof Map<?, ?> kakaoAccount) {
            Object email = kakaoAccount.get("email");
            if (email instanceof String s && !s.isBlank()) {
                flat.put("email", s);
            }

            Object profile = kakaoAccount.get("profile");
            if (profile instanceof Map<?, ?> p && p.get("nickname") != null) {
                flat.put("nickname", p.get("nickname"));
            }
        }

        // OAuthLoginSuccessHandler가 provider별 principalName을 고를 때 사용.
        flat.put("provider", "kakao");

        return flat;
    }

    /** Naver: 프로필은 response 객체 안에 있음 */
    private static Map<String, Object> flattenNaverAttributes(Map<String, Object> attributes) {
        Map<String, Object> flat = new LinkedHashMap<>();
        Object response = attributes.get("response");
        if (response instanceof Map<?, ?> naverProfile) {
            for (Map.Entry<?, ?> entry : naverProfile.entrySet()) {
                if (entry.getKey() instanceof String key && entry.getValue() != null) {
                    flat.put(key, entry.getValue());
                }
            }
        }

        flat.put("provider", "naver");

        return flat;
    }

    /** Google은 openid scope → OidcUser */
    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcUserService delegate = new OidcUserService();

        return userRequest -> {
            OidcUser user = delegate.loadUser(userRequest);

            // nameAttributeKey=email. JWT sub 후보로 이메일을 쓰기 쉽게 펼침.
            return new DefaultOidcUser(
                    user.getAuthorities(), user.getIdToken(), user.getUserInfo(), "email");
        };
    }
}
