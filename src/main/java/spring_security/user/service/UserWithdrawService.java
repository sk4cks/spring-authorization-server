package spring_security.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.common.security.InternalApiKeyVerifier;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;
import spring_security.user.domain.SysUser;
import spring_security.user.repository.SysUserQueryRepository;
import spring_security.user.repository.SysUserRepository;

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
