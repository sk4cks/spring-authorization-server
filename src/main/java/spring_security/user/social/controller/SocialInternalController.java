package spring_security.user.social.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import spring_security.user.social.dto.SocialRegisterRequest;
import spring_security.user.social.dto.SocialStatusResponse;
import spring_security.user.social.service.SocialRegisterService;

import java.util.Map;

@RestController
@RequestMapping("/auth/social")
@RequiredArgsConstructor
public class SocialInternalController {

    private final SocialRegisterService socialRegisterService;

    /** BFF 전용 — SNS 계정 SYS_USER 등록 여부. API key: InternalApiKeyInterceptor */
    @GetMapping("/users/status")
    public ResponseEntity<SocialStatusResponse> status(
            @RequestParam String provider,
            @RequestParam String externalId) {
        return ResponseEntity.ok(socialRegisterService.getStatus(provider, externalId));
    }

    /** BFF 전용 — SNS 최초 로그인 userId 선택 후 SYS_USER INSERT + 토큰 발급 */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody SocialRegisterRequest request) {
        return ResponseEntity.ok(socialRegisterService.register(request));
    }
}
