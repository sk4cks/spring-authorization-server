package spring_security.google;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * BFF Gmail 연동용 Google access token. 내부 API key 필요.
 */
@RestController
@RequestMapping("/auth/google")
@RequiredArgsConstructor
public class GoogleGmailTokenController {

    private final GoogleGmailTokenService googleGmailTokenService;

    /** BFF 전용. API key: InternalApiKeyInterceptor */
    @GetMapping("/access-token")
    public ResponseEntity<Map<String, String>> accessToken(@RequestParam String principal) {
        // principal = oauth2Login 때 저장한 name(보통 Google email).
        String accessToken = googleGmailTokenService.getAccessToken(principal);

        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }
}
