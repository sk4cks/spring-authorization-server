package spring_security.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import spring_security.user.domain.AuthProvider;
import spring_security.user.domain.SysUser;
import spring_security.user.domain.UserStatus;
import spring_security.user.repository.SysUserQueryRepository;

/**
 * 로컬 로그인 전용 UserDetailsService.
 * SNS 계정은 passwordHash가 없어서 이 경로 로그인 제외.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final SysUserQueryRepository sysUserQueryRepository;

    /** LOCAL+ACTIVE+미탈퇴 사용자 조회. SNS·탈퇴는 제외. */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // LOCAL + ACTIVE + DEL_YN=N. SNS 계정·탈퇴 계정은 비밀번호 로그인 제외.
        SysUser user = sysUserQueryRepository
                .findByUserIdAndAuthProviderAndStatus(username, AuthProvider.LOCAL, UserStatus.ACTIVE)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // 가입 직후 해시가 비면 DaoAuthenticationProvider가 NPE 나기 전에 거절.
        if (user.getPasswordHash() == null) {
            throw new UsernameNotFoundException("Password not configured: " + username);
        }

        // password는 {bcrypt}... DelegatingPasswordEncoder가 prefix로 비교.
        return User.builder()
                .username(user.getUserId())
                .password(user.getPasswordHash())
                .roles("USER")
                .build();
    }
}
