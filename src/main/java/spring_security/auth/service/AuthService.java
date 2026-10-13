package spring_security.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import spring_security.auth.dto.LoginRequest;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;

import java.util.HashMap;
import java.util.Map;

/**
 * 로컬 로그인. BFF가 {@code POST /api/auth/login}으로 여기 {@code POST /auth/login} 호출.
 * 아이디/비밀번호 확인 뒤 {@link AccessTokenService}가 JWT를 만들어 반환.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final AccessTokenService accessTokenService;

    /** userId/password 검증 뒤 access/refresh JWT 발급. */
    public Map<String, Object> login(LoginRequest param) {
        // Spring Security가 userId/password를 검사할 때 쓰는 객체.
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(param.userId(), param.password());

        Authentication auth;
        try {
            // CustomUserDetailsService가 LOCAL+ACTIVE 사용자 조회, DelegatingPasswordEncoder로 비교.
            auth = authenticationManager.authenticate(authToken);

        } catch (AuthenticationException ex) {
            // BadCredentials / UsernameNotFound 를 같은 401로 묶음. 존재 여부는 숨김.
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS, ex);
        }

        // JWT 발급 결과에 로그인 id를 붙여 BFF가 그대로 프론트에 전달.
        Map<String, Object> result = new HashMap<>(accessTokenService.issueAccessToken(auth, param.userId()));
        result.put("userId", param.userId());

        return result;
    }
}
