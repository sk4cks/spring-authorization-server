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

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final SysUserQueryRepository sysUserQueryRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser user = sysUserQueryRepository
                .findByUserIdAndAuthProviderAndStatus(username, AuthProvider.LOCAL, UserStatus.ACTIVE)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        if (user.getPasswordHash() == null) {
            throw new UsernameNotFoundException("Password not configured: " + username);
        }

        return User.builder()
                .username(user.getUserId())
                .password(user.getPasswordHash())
                .roles("USER")
                .build();
    }
}
