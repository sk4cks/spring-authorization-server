package spring_security.google;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;

import java.time.Instant;

/**
 * Google oauth2Login 때 저장한 Gmail access token.
 * BFF가 Gmail API를 부를 때 내부 API로 조회.
 */
@Service
@RequiredArgsConstructor
public class GoogleGmailTokenService {

    private static final String GOOGLE_REGISTRATION_ID = "google";

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final OAuth2AuthorizedClientManager authorizedClientManager;

    /** 저장된 Google access token 조회. */
    public String getAccessToken(String principal) {
        if (!StringUtils.hasText(principal)) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "principal required");
        }

        return getValidAccessToken(principal);
    }

    /** 만료 임박이면 refresh 후 access token 조회. */
    public String getValidAccessToken(String principalName) {
        // oauth2Login 성공 시 InMemoryOAuth2AuthorizedClientService에 저장된 클라이언트.
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                GOOGLE_REGISTRATION_ID, principalName);

        if (client == null) {
            throw new ApiException(ErrorCode.GOOGLE_GMAIL_NOT_LINKED);
        }

        // 만료 임박이면 refresh_token grant로 새 access 수신.
        if (isExpiredSoon(client)) {
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                    .withClientRegistrationId(GOOGLE_REGISTRATION_ID)
                    .principal(authentication(principalName))
                    .build();

            client = authorizedClientManager.authorize(authorizeRequest);

            if (client == null || client.getAccessToken() == null) {
                throw new ApiException(ErrorCode.GOOGLE_GMAIL_NOT_LINKED);
            }
        }

        return client.getAccessToken().getTokenValue();
    }

    /** expiresAt이 있고 60초 안이면 곧 만료로 보는 확인. */
    private static boolean isExpiredSoon(OAuth2AuthorizedClient client) {
        Instant expiresAt = client.getAccessToken().getExpiresAt();

        // expiresAt이 없으면 만료 여부를 모르니 그대로 사용. 60초 여유.
        return expiresAt != null && expiresAt.isBefore(Instant.now().plusSeconds(60));
    }

    /** principal name으로 AuthorizedClient 조회용 인증 객체 생성. */
    private static Authentication authentication(String principalName) {
        // AuthorizedClientManager가 principal name으로 저장된 클라이언트 조회.
        return new UsernamePasswordAuthenticationToken(principalName, "N/A");
    }
}
