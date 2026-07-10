package spring_security.user.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring_security.user.dto.UserResponse;
import spring_security.user.service.UserQueryService;
import spring_security.user.service.UserWithdrawService;

@RestController
@RequestMapping("/auth/users")
@RequiredArgsConstructor
public class UserInternalController {

    private final UserQueryService userQueryService;
    private final UserWithdrawService userWithdrawService;

    /** BFF 전용 — SYS_USER 조회 (비밀번호 미포함) */
    @GetMapping("/{userId}")
    public ResponseEntity<UserResponse> getUser(
            @PathVariable String userId,
            @RequestHeader(value = "X-Internal-Api-Key", required = false) String apiKey) {
        return ResponseEntity.ok(userQueryService.findByUserIdForInternal(apiKey, userId));
    }

    /** BFF 전용 — 회원 탈퇴(soft delete) */
    @PostMapping("/{userId}/withdraw")
    public ResponseEntity<Void> withdraw(
            @PathVariable String userId,
            @RequestHeader(value = "X-Internal-Api-Key", required = false) String apiKey) {
        userWithdrawService.withdrawForInternal(apiKey, userId);
        return ResponseEntity.noContent().build();
    }
}
