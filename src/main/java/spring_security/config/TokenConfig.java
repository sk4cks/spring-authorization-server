package spring_security.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class TokenConfig {

    /** 로컬 로그인 JWT 서명에 쓰는 엔코더. */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        // AccessTokenService가 로컬 로그인 JWT를 이 엔코더로 서명.
        return new NimbusJwtEncoder(jwkSource);
    }
}
