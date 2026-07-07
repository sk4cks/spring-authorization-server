package spring_security.api.user.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring_security.api.user.dto.UserResponse;
import spring_security.api.user.service.UserQueryService;

@RestController
@RequestMapping("/auth/users")
@RequiredArgsConstructor
public class UserInternalController {

    private final UserQueryService userQueryService;

    /** BFF 전용 — SYS_USER 조회 (비밀번호 미포함) */
    @GetMapping("/{userId}")
    public ResponseEntity<UserResponse> getUser(
            @PathVariable String userId,
            @RequestHeader(value = "X-Internal-Api-Key", required = false) String apiKey) {
        return ResponseEntity.ok(userQueryService.findByUserIdForInternal(apiKey, userId));
    }
}
