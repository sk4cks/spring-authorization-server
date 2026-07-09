package spring_security.api.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.api.auth.security.InternalApiKeyVerifier;
import spring_security.api.auth.service.AccessTokenService;
import spring_security.api.common.exception.AppException;
import spring_security.api.common.exception.ErrorCode;
import spring_security.api.user.domain.AuthProvider;
import spring_security.api.user.domain.SysUser;
import spring_security.api.user.dto.SocialRegisterRequest;
import spring_security.api.user.dto.SocialStatusResponse;
import spring_security.api.user.repository.SysUserQueryRepository;
import spring_security.api.user.repository.SysUserRepository;

import java.util.LinkedHashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class SocialRegisterService {

    private final InternalApiKeyVerifier internalApiKeyVerifier;
    private final SysUserRepository sysUserRepository;
    private final SysUserQueryRepository sysUserQueryRepository;
    private final AccessTokenService accessTokenService;

    @Value("${app.mail.domain}")
    private String mailDomain;

    public SocialStatusResponse getStatusForInternal(String apiKey, String provider, String externalId) {
        internalApiKeyVerifier.requireValid(apiKey);
        AuthProvider authProvider = parseProvider(provider);
        return sysUserQueryRepository
                .findByAuthProviderAndExternalId(authProvider, externalId)
                .map(user -> new SocialStatusResponse(true, user.getUserId()))
                .orElseGet(() -> new SocialStatusResponse(false, null));
    }

    @Transactional
    public Map<String, Object> registerForInternal(String apiKey, SocialRegisterRequest request) {
        internalApiKeyVerifier.requireValid(apiKey);
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

        Map<String, Object> result = new LinkedHashMap<>(accessTokenService.issueAccessTokenForUser(saved));
        result.put("userId", saved.getUserId());
        return result;
    }

    private static AuthProvider parseProvider(String provider) {
        try {
            return AuthProvider.valueOf(provider.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new AppException(ErrorCode.INVALID_REQUEST, "Unknown provider: " + provider);
        }
    }
}
