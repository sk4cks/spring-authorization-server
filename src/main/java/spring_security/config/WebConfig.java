package spring_security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // 프론트는 보통 BFF만 치므로 로컬 개발용. 자격 증명은 쿠키/Authorization 헤더.
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:8080")
                .allowedMethods("GET", "POST")
                .allowedHeaders("*")
                .exposedHeaders("Set-Cookie", "Authorization")
                .allowCredentials(true)
                .maxAge(3600);
    }
}
