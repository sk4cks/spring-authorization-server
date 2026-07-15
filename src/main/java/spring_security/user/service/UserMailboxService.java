package spring_security.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;
import spring_security.mail.MailboxPasswordCipher;
import spring_security.mailcow.MailcowProperties;
import spring_security.user.domain.SysUser;
import spring_security.user.dto.MailboxCredentialsResponse;
import spring_security.user.repository.SysUserQueryRepository;

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
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND, "User not found: " + userId));

        if (!StringUtils.hasText(user.getMailboxPasswordEnc())) {
            throw new AppException(ErrorCode.USER_NOT_FOUND, "Mailbox credentials not found: " + userId);
        }

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
