package spring_security.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import spring_security.auth.dto.LoginRequest;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final AccessTokenService accessTokenService;

    public Map<String, Object> login(LoginRequest param) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(param.userId(), param.password());

        Authentication auth = authenticationManager.authenticate(authToken);

        Map<String, Object> result = new HashMap<>(accessTokenService.issueAccessToken(auth, param.userId()));
        result.put("userId", param.userId());
        return result;
    }
}
