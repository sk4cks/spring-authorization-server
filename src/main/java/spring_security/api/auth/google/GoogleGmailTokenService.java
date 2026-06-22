package spring_security.api.auth.google;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class GoogleGmailTokenService {

    private static final String GOOGLE_REGISTRATION_ID = "google";

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final OAuth2AuthorizedClientManager authorizedClientManager;

    public String getValidAccessToken(String principalName) {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                GOOGLE_REGISTRATION_ID, principalName);
        if (client == null) {
            throw new GoogleGmailTokenNotFoundException(principalName);
        }

        if (isExpiredSoon(client)) {
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                    .withClientRegistrationId(GOOGLE_REGISTRATION_ID)
                    .principal(authentication(principalName))
                    .build();
            client = authorizedClientManager.authorize(authorizeRequest);
            if (client == null || client.getAccessToken() == null) {
                throw new GoogleGmailTokenNotFoundException(principalName);
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
