package spring_security.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;
import spring_security.mail.MailboxPasswordCipher;
import spring_security.mailcow.MailcowClient;
import spring_security.user.domain.SysUser;
import spring_security.user.dto.RegisterRequest;
import spring_security.user.dto.UserIdAvailabilityResponse;
import spring_security.user.dto.UserResponse;
import spring_security.user.repository.SysUserQueryRepository;
import spring_security.user.repository.SysUserRepository;

@Service
@RequiredArgsConstructor
public class UserRegisterService {

    private static final String USER_ID_PATTERN = "^[a-zA-Z0-9_]+$";

    private final SysUserRepository sysUserRepository;
    private final SysUserQueryRepository sysUserQueryRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailcowClient mailcowClient;
    private final MailboxPasswordCipher mailboxPasswordCipher;

    @Value("${app.mail.domain}")
    private String mailDomain;

    /**
     * 회원가입 전 아이디 사용 가능 여부.
     * register 와 동일하게 userId + 메일주소(userId@domain) 중복을 본다.
     */
    @Transactional(readOnly = true)
    public UserIdAvailabilityResponse checkUserId(String userId) {
        validateUserIdFormat(userId);
        String mailAddress = userId + "@" + mailDomain;
        boolean taken = sysUserQueryRepository.existsByUserId(userId)
                || sysUserQueryRepository.existsByMailAddress(mailAddress);

        return new UserIdAvailabilityResponse(userId, !taken);
    }

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

    private void validateUserIdFormat(String userId) {
        if (!StringUtils.hasText(userId)) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "아이디를 입력해 주세요");
        }
        if (userId.length() < 3 || userId.length() > 64) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "아이디는 3자 이상 64자 이하여야 합니다");
        }
        if (!userId.matches(USER_ID_PATTERN)) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "아이디는 영문, 숫자, 밑줄(_)만 사용할 수 있습니다");
        }
    }
}
