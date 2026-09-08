package spring_security.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring_security.auth.dto.LoginRequest;
import spring_security.auth.service.AuthService;

import java.util.Map;

/**
 * 로컬 로그인. BFF만 호출한다. 프론트는 :9000에 직접 붙지 않는다.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /** BFF 전용 — 프론트는 API만 호출하고 이 endpoint는 API가 server-to-server로 사용 */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest param) {
        // userId/password를 검증한 뒤 JWT를 바로 내려준다.
        return ResponseEntity.ok(authService.login(param));
    }
}
