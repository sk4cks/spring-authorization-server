package spring_security.google;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth/google")
@RequiredArgsConstructor
public class GoogleGmailTokenController {

    private final GoogleGmailTokenService googleGmailTokenService;

    /** BFF 전용. API key: InternalApiKeyInterceptor */
    @GetMapping("/access-token")
    public ResponseEntity<Map<String, String>> accessToken(@RequestParam String principal) {
        String accessToken = googleGmailTokenService.getAccessToken(principal);
        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }
}
