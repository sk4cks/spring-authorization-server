package spring_security.user.social.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.auth.service.AccessTokenService;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;
import spring_security.mail.MailboxPasswordCipher;
import spring_security.mailcow.MailcowClient;
import spring_security.user.domain.AuthProvider;
import spring_security.user.domain.SysUser;
import spring_security.user.repository.SysUserQueryRepository;
import spring_security.user.repository.SysUserRepository;
import spring_security.user.social.dto.SocialRegisterRequest;
import spring_security.user.social.dto.SocialStatusResponse;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SNS 온보딩. JWT sns_* 클레임으로 이미 온 사용자가 userId를 고르면 SYS_USER를 만들고 토큰을 준다.
 */
@Service
@RequiredArgsConstructor
public class SocialRegisterService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SysUserRepository sysUserRepository;
    private final SysUserQueryRepository sysUserQueryRepository;
    private final AccessTokenService accessTokenService;
    private final MailcowClient mailcowClient;
    private final MailboxPasswordCipher mailboxPasswordCipher;

    @Value("${app.mail.domain}")
    private String mailDomain;

    public SocialStatusResponse getStatus(String provider, String externalId) {
        AuthProvider authProvider = parseProvider(provider);

        // SNS provider+외부 id로 SYS_USER가 있으면 온보딩 완료.
        return sysUserQueryRepository
                .findByAuthProviderAndExternalId(authProvider, externalId)
                .map(user -> new SocialStatusResponse(true, user.getUserId()))
                .orElseGet(() -> new SocialStatusResponse(false, null));
    }

    @Transactional
    public Map<String, Object> register(SocialRegisterRequest request) {
        AuthProvider authProvider = parseProvider(request.provider());

        // 같은 Google/Kakao/Naver 계정이 이미 있으면 아이디를 또 고르지 않는다.
        if (sysUserQueryRepository.existsByAuthProviderAndExternalId(authProvider, request.externalId())) {
            throw new ApiException(ErrorCode.USER_ALREADY_EXISTS, "Social account already registered");
        }

        // 로컬 가입과 같은 userId 공간. 이미 있으면 다른 아이디를 고르게 한다.
        if (sysUserQueryRepository.existsByUserId(request.userId())) {
            throw new ApiException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

        String mailAddress = request.userId() + "@" + mailDomain;

        if (sysUserQueryRepository.existsByMailAddress(mailAddress)) {
            throw new ApiException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

        // SNS 이메일은 선택. 공백만 오면 null로 저장한다.
        String externalEmail = request.externalEmail();

        if (externalEmail != null && externalEmail.isBlank()) {
            externalEmail = null;
        }

        SysUser user = SysUser.createSocial(
                request.userId(), mailAddress, authProvider, request.externalId(), externalEmail);
        SysUser saved = sysUserRepository.save(user);

        // SNS는 앱 비밀번호가 없음 → 랜덤 메일함 비번 + IMAP용 암호 저장.
        String mailboxPassword = randomMailboxPassword();
        mailcowClient.createMailbox(request.userId(), mailDomain, request.userId(), mailboxPassword);
        saved.assignMailboxPasswordEnc(mailboxPasswordCipher.encrypt(mailboxPassword));

        // 온보딩 직후 바로 SPA에 넣을 토큰. SecurityContext Authentication은 없다.
        Map<String, Object> result = new LinkedHashMap<>(accessTokenService.issueAccessTokenForUser(saved));
        result.put("userId", saved.getUserId());

        return result;
    }

    private static String randomMailboxPassword() {
        byte[] bytes = new byte[24];
        SECURE_RANDOM.nextBytes(bytes);

        // URL-safe라 Mailcow 비밀번호에 +/ 가 안 들어간다.
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static AuthProvider parseProvider(String provider) {
        try {
            // JWT sns_provider / 쿼리 파라미터는 google 처럼 소문자로 올 수 있다.
            return AuthProvider.valueOf(provider.trim().toUpperCase());

        } catch (IllegalArgumentException ex) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "Unknown provider: " + provider);
        }
    }
}
