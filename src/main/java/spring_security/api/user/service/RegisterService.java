package spring_security.api.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring_security.api.user.domain.SysUser;
import spring_security.api.user.dto.RegisterRequest;
import spring_security.api.user.dto.UserResponse;
import spring_security.api.common.exception.AppException;
import spring_security.api.common.exception.ErrorCode;
import spring_security.api.user.repository.SysUserQueryRepository;
import spring_security.api.user.repository.SysUserRepository;

@Service
@RequiredArgsConstructor
public class RegisterService {

    private final SysUserRepository sysUserRepository;
    private final SysUserQueryRepository sysUserQueryRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.mail.domain}")
    private String mailDomain;

    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (sysUserQueryRepository.existsByUserId(request.userId())) {
            throw new AppException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

        String mailAddress = request.userId() + "@" + mailDomain;
        if (sysUserQueryRepository.existsByMailAddress(mailAddress)) {
            throw new AppException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: " + request.userId());
        }

        String passwordHash = passwordEncoder.encode(request.password());
        SysUser user = SysUser.createLocal(request.userId(), mailAddress, passwordHash);
        SysUser saved = sysUserRepository.save(user);
        return UserResponse.from(saved);
    }
}
