package spring_security.api.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.api.auth.security.InternalApiKeyVerifier;
import spring_security.api.common.exception.AppException;
import spring_security.api.common.exception.ErrorCode;
import spring_security.api.user.domain.SysUser;
import spring_security.api.user.repository.SysUserQueryRepository;
import spring_security.api.user.repository.SysUserRepository;

@Service
@RequiredArgsConstructor
public class UserWithdrawService {

    private final InternalApiKeyVerifier internalApiKeyVerifier;
    private final SysUserQueryRepository sysUserQueryRepository;
    private final SysUserRepository sysUserRepository;

    /** BFF 전용 — 회원 탈퇴(soft delete) */
    @Transactional
    public void withdrawForInternal(String apiKey, String userId) {
        internalApiKeyVerifier.requireValid(apiKey);
        SysUser user = sysUserQueryRepository
                .findByUserId(userId)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND, "User not found: " + userId));
        user.softDelete(user.getUserSeq());
        sysUserRepository.save(user);
    }
}
