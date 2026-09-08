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

    public static UserResponse from(SysUser user) {
        // passwordHash·메일함 암호는 넣지 않는다.
        return new UserResponse(
                user.getUserSeq(),
                user.getUserId(),
                user.getMailAddress(),
                user.getAuthProvider(),
                user.getStatus());
    }
}
