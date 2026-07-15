package spring_security.common.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 내부 API 경로에만 API key 인터셉터 적용.
 * 공개: {@code /auth/login}, {@code /auth/register}, {@code /auth/social/prepare/**}
 */
@Configuration
@RequiredArgsConstructor
public class InternalApiKeyWebConfig implements WebMvcConfigurer {

    private final InternalApiKeyInterceptor internalApiKeyInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(internalApiKeyInterceptor)
                .addPathPatterns(
                        "/auth/users/**",
                        "/auth/social/users/**",
                        "/auth/social/register",
                        "/auth/google/**");
    }
}
