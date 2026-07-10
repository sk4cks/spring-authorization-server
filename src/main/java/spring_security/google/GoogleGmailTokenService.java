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
import spring_security.common.security.InternalApiKeyVerifier;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class GoogleGmailTokenService {

    private static final String GOOGLE_REGISTRATION_ID = "google";

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final InternalApiKeyVerifier internalApiKeyVerifier;

    public String getAccessTokenForInternal(String apiKey, String principal) {
        internalApiKeyVerifier.requireValid(apiKey);
        if (!StringUtils.hasText(principal)) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "principal required");
        }
        return getValidAccessToken(principal);
    }

    public String getValidAccessToken(String principalName) {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                GOOGLE_REGISTRATION_ID, principalName);
        if (client == null) {
            throw new AppException(ErrorCode.GOOGLE_GMAIL_NOT_LINKED);
        }

        if (isExpiredSoon(client)) {
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                    .withClientRegistrationId(GOOGLE_REGISTRATION_ID)
                    .principal(authentication(principalName))
                    .build();

            client = authorizedClientManager.authorize(authorizeRequest);
            if (client == null || client.getAccessToken() == null) {
                throw new AppException(ErrorCode.GOOGLE_GMAIL_NOT_LINKED);
            }
        }

        return client.getAccessToken().getTokenValue();
    }

    private static boolean isExpiredSoon(OAuth2AuthorizedClient client) {
        Instant expiresAt = client.getAccessToken().getExpiresAt();
        return expiresAt != null && expiresAt.isBefore(Instant.now().plusSeconds(60));
    }

    private static Authentication authentication(String principalName) {
        return new UsernamePasswordAuthenticationToken(principalName, "N/A");
    }
}
