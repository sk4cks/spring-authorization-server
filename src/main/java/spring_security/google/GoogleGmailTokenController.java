package spring_security.google;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
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

    @GetMapping("/access-token")
    public ResponseEntity<Map<String, String>> accessToken(
            @RequestParam String principal,
            @RequestHeader(value = "X-Internal-Api-Key", required = false) String apiKey) {
        String accessToken = googleGmailTokenService.getAccessTokenForInternal(apiKey, principal);
        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }
}
