package spring_security.user.dto;

import spring_security.user.domain.AuthProvider;
import spring_security.user.domain.SysUser;
import spring_security.user.domain.UserStatus;

public record UserResponse(
        Long userSeq,
        String userId,
        String mailAddress,
        AuthProvider authProvider,
        UserStatus status) {

    /** SYS_USER를 응답으로 변환. 비밀번호·메일함 암호는 제외. */
    public static UserResponse from(SysUser user) {
        // passwordHash·메일함 암호는 제외.
        return new UserResponse(
                user.getUserSeq(),
                user.getUserId(),
                user.getMailAddress(),
                user.getAuthProvider(),
                user.getStatus());
    }
}
