package spring_security.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;
import spring_security.mail.MailboxPasswordCipher;
import spring_security.mailcow.MailcowClient;
import spring_security.user.domain.SysUser;
import spring_security.user.dto.RegisterRequest;
import spring_security.user.dto.UserResponse;
import spring_security.user.repository.SysUserQueryRepository;
import spring_security.user.repository.SysUserRepository;

@Service
@RequiredArgsConstructor
public class RegisterService {

    private final SysUserRepository sysUserRepository;
    private final SysUserQueryRepository sysUserQueryRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailcowClient mailcowClient;
    private final MailboxPasswordCipher mailboxPasswordCipher;

    @Value("${app.mail.domain}")
    private String mailDomain;

    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (sysUserQueryRepository.existsByUserId(request.userId())) {
            throw new AppException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

        String mailAddress = request.userId() + "@" + mailDomain;
        if (sysUserQueryRepository.existsByMailAddress(mailAddress)) {
            throw new AppException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

        String passwordHash = passwordEncoder.encode(request.password());
        SysUser user = SysUser.createLocal(request.userId(), mailAddress, passwordHash);
        SysUser saved = sysUserRepository.save(user);

        // 같은 비밀번호로 Mailcow 메일함 생성 + IMAP용 암호 저장. 실패 시 트랜잭션 롤백.
        mailcowClient.createMailbox(request.userId(), mailDomain, request.userId(), request.password());
        saved.assignMailboxPasswordEnc(mailboxPasswordCipher.encrypt(request.password()));

        return UserResponse.from(saved);
    }
}
