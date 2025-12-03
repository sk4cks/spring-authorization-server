package spring_security.api.tempAuth;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.Authentication;

import java.time.Instant;

@Getter
@AllArgsConstructor
public class TempAuthToken {
    private String token;
    private Authentication authentication;
    private Instant expiresAt;

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}