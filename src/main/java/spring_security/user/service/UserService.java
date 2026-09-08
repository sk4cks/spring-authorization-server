package spring_security.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;
import spring_security.user.domain.SysUser;
import spring_security.user.dto.UserResponse;
import spring_security.user.repository.SysUserQueryRepository;
import spring_security.user.repository.SysUserRepository;

/** 로컬 유저 조회·탈퇴 (가입은 {@link UserRegisterService}). */
@Service
@RequiredArgsConstructor
public class UserService {

    private final SysUserQueryRepository sysUserQueryRepository;
    private final SysUserRepository sysUserRepository;

    @Transactional(readOnly = true)
    public UserResponse findByUserId(String userId) {
        // 비밀번호·메일함 암호는 UserResponse에 넣지 않는다.
        return sysUserQueryRepository.findByUserId(userId)
                .map(UserResponse::from)
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND, "User not found: " + userId));
    }

    /** BFF 전용 — 회원 탈퇴(soft delete). API key: InternalApiKeyInterceptor */
    @Transactional
    public void withdraw(String userId) {
        SysUser user = sysUserQueryRepository
                .findByUserId(userId)
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND, "User not found: " + userId));

        // DEL_YN=Y, STATUS=INACTIVE. 로그인·주소록 디렉터리에서 빠진다.
        user.softDelete(user.getUserSeq());

        // dirty checking으로도 UPDATE 되지만, 명시 save로 커밋 전에 반영을 고정한다.
        sysUserRepository.save(user);
    }
}
