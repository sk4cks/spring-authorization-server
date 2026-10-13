package spring_security.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Google Gmail 토큰 저장·갱신과, Google authorize 때 refresh를 받기 위한 파라미터.
 */
@Configuration
public class OAuth2ClientConfig {

    /** principal name으로 access/refresh를 꺼내는 저장소. */
    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
        // GoogleGmailTokenService가 principal name으로 access/refresh 조회.
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    /** access가 곧 만료되면 refresh_token grant로 교체. */
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientService authorizedClientService) {
        // access가 곧 만료되면 refresh_token grant로 교체.
        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientService);

        manager.setAuthorizedClientProvider(provider);

        return manager;
    }

    /** Google authorize에 offline·consent 파라미터를 붙이는 resolver. */
    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver delegate = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, "/oauth2/authorization");

        return new OAuth2AuthorizationRequestResolver() {
            /** 요청 URL에서 authorization request 조회 후 Google 파라미터 추가. */
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                return customizeGoogle(delegate.resolve(request));
            }

            /** registration id로 authorization request 조회 후 Google 파라미터 추가. */
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
                return customizeGoogle(delegate.resolve(request, clientRegistrationId), clientRegistrationId);
            }
        };
    }

    /** Google이면 access_type=offline, prompt=consent 추가. */
    private static OAuth2AuthorizationRequest customizeGoogle(OAuth2AuthorizationRequest request) {
        if (request == null) {
            return null;
        }

        Object registrationId = request.getAttribute("registration_id");
        if (registrationId == null) {
            return request;
        }

        return customizeGoogle(request, registrationId.toString());
    }

    /** registration이 Google이면 offline·consent 파라미터 추가. */
    private static OAuth2AuthorizationRequest customizeGoogle(OAuth2AuthorizationRequest request, String clientRegistrationId) {
        if (request == null || !"google".equals(clientRegistrationId)) {
            return request;
        }

        // access_type=offline 이어야 refresh_token 수신. prompt=consent는 매번 동의를 받아 refresh를 놓치지 않게 요청.
        return OAuth2AuthorizationRequest.from(request)
                .additionalParameters(params -> {
                    params.put("access_type", "offline");
                    params.put("prompt", "consent");
                })
                .build();
    }
}
