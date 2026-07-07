package spring_security.api.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.api.auth.security.InternalApiKeyVerifier;
import spring_security.api.common.exception.AppException;
import spring_security.api.common.exception.ErrorCode;
import spring_security.api.user.dto.UserResponse;
import spring_security.api.user.repository.SysUserQueryRepository;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserQueryService {

    private final SysUserQueryRepository sysUserQueryRepository;
    private final InternalApiKeyVerifier internalApiKeyVerifier;

    public UserResponse findByUserIdForInternal(String apiKey, String userId) {
        internalApiKeyVerifier.requireValid(apiKey);
        return findByUserId(userId);
    }

    public UserResponse findByUserId(String userId) {
        return sysUserQueryRepository.findByUserId(userId)
                .map(UserResponse::from)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND, "User not found: " + userId));
    }
}
