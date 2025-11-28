package spring_security.api.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import spring_security.api.auth.model.SignInDTO;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;


    public Map<String, Object> login(SignInDTO param) {
        Map<String, Object> response = new HashMap<>();

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(param.userId(), param.password());

        Authentication auth = authenticationManager.authenticate(authToken);

        // ★ 인증 성공 시 OAuth2 Authorization Server 토큰 발급 로직으로 연결

        return response;
    }
}
