package spring_security.user.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import spring_security.user.dto.RegisterRequest;
import spring_security.user.dto.UserIdAvailabilityResponse;
import spring_security.user.dto.UserResponse;
import spring_security.user.service.UserRegisterService;

/**
 * 로컬 회원가입. permitAll. 내부 API key는 필요 없다.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class UserRegisterController {

    private final UserRegisterService userRegisterService;

    @GetMapping("/check-userid")
    public ResponseEntity<UserIdAvailabilityResponse> checkUserId(@RequestParam String userId) {
        // userId + userId@domain 중복. available=true 이면 가입 가능.
        return ResponseEntity.ok(userRegisterService.checkUserId(userId));
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse response = userRegisterService.register(request);

        // SYS_USER INSERT + Mailcow 메일함 생성 후 201.
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
