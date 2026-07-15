package spring_security.user.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring_security.user.dto.MailboxCredentialsResponse;
import spring_security.user.dto.UserResponse;
import spring_security.user.service.UserMailboxService;
import spring_security.user.service.UserQueryService;
import spring_security.user.service.UserWithdrawService;

@RestController
@RequestMapping("/auth/users")
@RequiredArgsConstructor
public class UserInternalController {

    private final UserQueryService userQueryService;
    private final UserWithdrawService userWithdrawService;
    private final UserMailboxService userMailboxService;

    /** BFF 전용 — SYS_USER 조회 (비밀번호 미포함). API key: InternalApiKeyInterceptor */
    @GetMapping("/{userId}")
    public ResponseEntity<UserResponse> getUser(@PathVariable String userId) {
        return ResponseEntity.ok(userQueryService.findByUserId(userId));
    }

    /** BFF 전용 — IMAP/SMTP 메일함 자격 (평문 password 포함) */
    @GetMapping("/{userId}/mailbox")
    public ResponseEntity<MailboxCredentialsResponse> getMailbox(@PathVariable String userId) {
        return ResponseEntity.ok(userMailboxService.getMailbox(userId));
    }

    /** BFF 전용 — 회원 탈퇴(soft delete) */
    @PostMapping("/{userId}/withdraw")
    public ResponseEntity<Void> withdraw(@PathVariable String userId) {
        userWithdrawService.withdraw(userId);
        return ResponseEntity.noContent().build();
    }
}
