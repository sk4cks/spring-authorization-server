package spring_security.common.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * BFF 전용 내부 API — {@code X-Internal-Api-Key} 검증.
 * 컨트롤러/서비스에서 헤더를 받을 필요 없음 ({@link InternalApiKeyWebConfig} 경로만).
 */
@Component
@RequiredArgsConstructor
public class InternalApiKeyInterceptor implements HandlerInterceptor {

    public static final String HEADER_NAME = "X-Internal-Api-Key";

    private final InternalApiKeyVerifier internalApiKeyVerifier;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        internalApiKeyVerifier.requireValid(request.getHeader(HEADER_NAME));
        return true;
    }
}
