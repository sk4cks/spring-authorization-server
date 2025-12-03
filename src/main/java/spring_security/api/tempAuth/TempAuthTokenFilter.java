package spring_security.api.tempAuth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class TempAuthTokenFilter extends OncePerRequestFilter {

    private final TempAuthTokenStore tempAuthTokenStore;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // /oauth2/authorize 요청에만 적용
        if (request.getRequestURI().startsWith("/oauth2/authorize")) {

            // 쿠키에서 임시 토큰 추출
            String tempToken = extractTempTokenFromCookies(request);

            if (tempToken == null) {
                // 헤더에서도 시도
                tempToken = request.getHeader("X-Temp-Auth-Token");
            }

            if (tempToken != null) {
                Optional<Authentication> authOptional = tempAuthTokenStore.getAuthentication(tempToken);

                if (authOptional.isPresent()) {
                    Authentication auth = authOptional.get();

                    // SecurityContext에 인증 정보 설정
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                    securityContext.setAuthentication(auth);
                    SecurityContextHolder.setContext(securityContext);

                    // 사용된 임시 토큰 삭제 (일회용)
                    tempAuthTokenStore.removeToken(tempToken);
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractTempTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("temp_auth_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }
}