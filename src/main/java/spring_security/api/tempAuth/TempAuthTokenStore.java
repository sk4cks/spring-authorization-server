package spring_security.api.tempAuth;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TempAuthTokenStore {

    private final Map<String, TempAuthToken> tokenStore = new ConcurrentHashMap<>();

    // 5분 유효한 임시 토큰 생성
    public String createToken(Authentication authentication) {
        String token = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now().plus(5, ChronoUnit.MINUTES);

        TempAuthToken tempAuthToken = new TempAuthToken(token, authentication, expiresAt);
        tokenStore.put(token, tempAuthToken);

        // 만료된 토큰 정리
        cleanExpiredTokens();

        return token;
    }

    public Optional<Authentication> getAuthentication(String token) {
        TempAuthToken tempAuthToken = tokenStore.get(token);

        if (tempAuthToken == null) {
            return Optional.empty();
        }

        if (tempAuthToken.isExpired()) {
            tokenStore.remove(token);
            return Optional.empty();
        }

        return Optional.of(tempAuthToken.getAuthentication());
    }

    public void removeToken(String token) {
        tokenStore.remove(token);
    }

    private void cleanExpiredTokens() {
        tokenStore.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }
}