package spring_security.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;
import spring_security.mail.MailboxPasswordCipher;
import spring_security.mailcow.MailcowClient;
import spring_security.user.domain.SysUser;
import spring_security.user.dto.RegisterRequest;
import spring_security.user.dto.UserIdAvailabilityResponse;
import spring_security.user.dto.UserResponse;
import spring_security.user.repository.SysUserQueryRepository;
import spring_security.user.repository.SysUserRepository;

/**
 * 로컬 회원가입. 메일 주소는 {@code userId@app.mail.domain} 고정.
 */
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
     * register 와 동일하게 userId + 메일주소(userId@domain) 중복 확인.
     */
    @Transactional(readOnly = true)
    public UserIdAvailabilityResponse checkUserId(String userId) {
        validateUserIdFormat(userId);

        // 로컬 가입 메일은 userId@도메인. 아이디 중복과 메일 중복을 같이 확인.
        String mailAddress = userId + "@" + mailDomain;
        boolean taken = sysUserQueryRepository.existsByUserId(userId)
                || sysUserQueryRepository.existsByMailAddress(mailAddress);

        // available=true 이면 가입 폼이 다음 단계로 이동.
        return new UserIdAvailabilityResponse(userId, !taken);
    }

    /** userId@도메인 메일함과 함께 로컬 계정 생성. */
    @Transactional
    public UserResponse register(RegisterRequest request) {
        // userId 유니크. 탈퇴하지 않은 행만 확인.
        if (sysUserQueryRepository.existsByUserId(request.userId())) {
            throw new ApiException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

        // 메일함 local-part도 userId라서 SYS_USER.MAIL_ADDRESS와 Mailcow 주소가 같음.
        String mailAddress = request.userId() + "@" + mailDomain;

        if (sysUserQueryRepository.existsByMailAddress(mailAddress)) {
            throw new ApiException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

        // DelegatingPasswordEncoder. DB에는 {bcrypt}... 형태로 저장.
        String passwordHash = passwordEncoder.encode(request.password());
        SysUser user = SysUser.createLocal(request.userId(), mailAddress, passwordHash);
        SysUser saved = sysUserRepository.save(user);

        // 같은 비밀번호로 Mailcow 메일함 생성 + IMAP용 암호 저장. 실패 시 트랜잭션 롤백.
        mailcowClient.createMailbox(request.userId(), mailDomain, request.userId(), request.password());
        saved.assignMailboxPasswordEnc(mailboxPasswordCipher.encrypt(request.password()));

        return UserResponse.from(saved);
    }

    /** 3~64자, 영문·숫자·밑줄만 허용하는 검사. */
    private void validateUserIdFormat(String userId) {
        if (!StringUtils.hasText(userId)) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "아이디를 입력해 주세요");
        }

        if (userId.length() < 3 || userId.length() > 64) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "아이디는 3자 이상 64자 이하여야 합니다");
        }

        // 메일 local-part와 같으므로 특수문자는 거절.
        if (!userId.matches(USER_ID_PATTERN)) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "아이디는 영문, 숫자, 밑줄(_)만 사용할 수 있습니다");
        }
    }
}
