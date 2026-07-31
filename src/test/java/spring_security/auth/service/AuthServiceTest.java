package spring_security.auth.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import spring_security.auth.dto.LoginRequest;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private AuthenticationManager authenticationManager;
    @Mock private AccessTokenService accessTokenService;
    @Mock private Authentication authentication;

    @InjectMocks private AuthService authService;

    @Test
    void login_returnsToken_whenCredentialsValid() {
        LoginRequest request = new LoginRequest("sk4cks", "1234");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(accessTokenService.issueAccessToken(authentication, "sk4cks"))
                .thenReturn(Map.of(
                        "access_token", "tok",
                        "token_type", "Bearer",
                        "expires_in", 3600L));

        Map<String, Object> result = authService.login(request);

        assertThat(result.get("access_token")).isEqualTo("tok");
        assertThat(result.get("userId")).isEqualTo("sk4cks");
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void login_wrapsAuthenticationFailureAsAppException() {
        LoginRequest request = new LoginRequest("sk4cks", "wrong");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("bad"));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_CREDENTIALS))
                .hasCauseInstanceOf(BadCredentialsException.class);
    }
}
