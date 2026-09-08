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
 * 로컬 로그인. BFF가 {@code POST /api/auth/login}으로 여기 {@code POST /auth/login}을 호출한다.
 * 아이디/비밀번호를 확인한 뒤 {@link AccessTokenService}가 JWT를 만들어 반환한다.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final AccessTokenService accessTokenService;

    public Map<String, Object> login(LoginRequest param) {
        // Spring Security가 userId/password를 검사할 때 쓰는 객체다.
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(param.userId(), param.password());

        Authentication auth;
        try {
            // CustomUserDetailsService가 LOCAL+ACTIVE 사용자를 찾고, DelegatingPasswordEncoder로 비교한다.
            auth = authenticationManager.authenticate(authToken);

        } catch (AuthenticationException ex) {
            // BadCredentials / UsernameNotFound 를 같은 401로 묶는다. 존재 여부를 드러내지 않는다.
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS, ex);
        }

        // JWT 발급 결과에 로그인 id를 붙여 BFF가 그대로 프론트에 넘긴다.
        Map<String, Object> result = new HashMap<>(accessTokenService.issueAccessToken(auth, param.userId()));
        result.put("userId", param.userId());

        return result;
    }
}
