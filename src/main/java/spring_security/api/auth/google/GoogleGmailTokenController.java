package spring_security.api.auth.google;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth/google")
@RequiredArgsConstructor
public class GoogleGmailTokenController {

    private final GoogleGmailTokenService googleGmailTokenService;

    @Value("${app.internal-api-key}")
    private String internalApiKey;

    @GetMapping("/access-token")
    public ResponseEntity<?> accessToken(
            @RequestParam String principal,
            @RequestHeader(value = "X-Internal-Api-Key", required = false) String apiKey) {
        if (!StringUtils.hasText(apiKey) || !apiKey.equals(internalApiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!StringUtils.hasText(principal)) {
            return ResponseEntity.badRequest().body(Map.of("error", "principal required"));
        }

        try {
            String accessToken = googleGmailTokenService.getValidAccessToken(principal);
            return ResponseEntity.ok(Map.of("accessToken", accessToken));
        } catch (GoogleGmailTokenNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of(
                            "code", "GOOGLE_GMAIL_NOT_LINKED",
                            "message", "Google login with Gmail scope required"));
        }
    }
}
