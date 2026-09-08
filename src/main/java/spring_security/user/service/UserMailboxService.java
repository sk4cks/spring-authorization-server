package spring_security.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;
import spring_security.mail.MailboxPasswordCipher;
import spring_security.mailcow.MailcowProperties;
import spring_security.user.domain.SysUser;
import spring_security.user.dto.MailboxCredentialsResponse;
import spring_security.user.repository.SysUserQueryRepository;

/**
 * BFF IMAP/SMTP 접속용 메일함 자격. 평문 비밀번호를 내려주므로 내부 API key만 통과한다.
 */
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserMailboxService {

    private final SysUserQueryRepository sysUserQueryRepository;
    private final MailboxPasswordCipher mailboxPasswordCipher;
    private final MailcowProperties mailcowProperties;

    public MailboxCredentialsResponse getMailbox(String userId) {
        SysUser user = sysUserQueryRepository
                .findByUserId(userId)
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND, "User not found: " + userId));

        // 가입 중 Mailcow 생성이 스킵됐거나 암호 저장 전이면 IMAP을 열 수 없다.
        if (!StringUtils.hasText(user.getMailboxPasswordEnc())) {
            throw new ApiException(ErrorCode.USER_NOT_FOUND, "Mailbox credentials not found: " + userId);
        }

        // DB에는 AES 암호문만 있다. BFF가 IMAP LOGIN에 쓸 평문으로 복호화한다.
        String plainPassword = mailboxPasswordCipher.decrypt(user.getMailboxPasswordEnc());

        return new MailboxCredentialsResponse(
                user.getMailAddress(),
                plainPassword,
                mailcowProperties.imapHost(),
                mailcowProperties.imapPort(),
                mailcowProperties.smtpHost(),
                mailcowProperties.smtpPort());
    }
}
