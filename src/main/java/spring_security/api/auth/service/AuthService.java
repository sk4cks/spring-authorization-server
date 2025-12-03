package spring_security.api.auth.service;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import spring_security.api.auth.model.SignInDTO;
import spring_security.api.tempAuth.TempAuthTokenStore;
import spring_security.util.AuthUtil;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;

    private final TempAuthTokenStore tempAuthTokenStore;


    public Map<String, Object> login(SignInDTO param, HttpServletResponse response) {
        Map<String, Object> resultMap = new HashMap<>();

        // 1. 사용자 인증
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(param.userId(), param.password());

        Authentication auth = authenticationManager.authenticate(authToken);

        // 2. 임시 인증 토큰 생성
        String tempToken = tempAuthTokenStore.createToken(auth);
        AuthUtil.setCookie("temp_auth_token", tempToken, response);

        return resultMap;
    }
}
