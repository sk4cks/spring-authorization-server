package spring_security.user.social.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.auth.service.AccessTokenService;
import spring_security.common.exception.AppException;
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
        return sysUserQueryRepository
                .findByAuthProviderAndExternalId(authProvider, externalId)
                .map(user -> new SocialStatusResponse(true, user.getUserId()))
                .orElseGet(() -> new SocialStatusResponse(false, null));
    }

    @Transactional
    public Map<String, Object> register(SocialRegisterRequest request) {
        AuthProvider authProvider = parseProvider(request.provider());

        if (sysUserQueryRepository.existsByAuthProviderAndExternalId(authProvider, request.externalId())) {
            throw new AppException(ErrorCode.USER_ALREADY_EXISTS, "Social account already registered");
        }
        if (sysUserQueryRepository.existsByUserId(request.userId())) {
            throw new AppException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

        String mailAddress = request.userId() + "@" + mailDomain;
        if (sysUserQueryRepository.existsByMailAddress(mailAddress)) {
            throw new AppException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

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

        Map<String, Object> result = new LinkedHashMap<>(accessTokenService.issueAccessTokenForUser(saved));
        result.put("userId", saved.getUserId());
        return result;
    }

    private static String randomMailboxPassword() {
        byte[] bytes = new byte[24];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static AuthProvider parseProvider(String provider) {
        try {
            return AuthProvider.valueOf(provider.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Unknown provider: " + provider);
        }
    }
}
