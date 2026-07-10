package spring_security.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.common.security.InternalApiKeyVerifier;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;
import spring_security.user.dto.UserResponse;
import spring_security.user.repository.SysUserQueryRepository;

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
