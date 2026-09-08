package spring_security.common.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;

/**
 * BFF가 보내는 {@code X-Internal-Api-Key}와 {@code app.internal-api-key}를 비교한다.
 */
@Component
public class InternalApiKeyVerifier {

    @Value("${app.internal-api-key}")
    private String internalApiKey;

    public boolean isValid(String apiKey) {
        // 빈 키는 항상 실패. 타이밍 공격까지는 보지 않는다.
        return StringUtils.hasText(apiKey) && apiKey.equals(internalApiKey);
    }

    public void requireValid(String apiKey) {
        if (!isValid(apiKey)) {
            throw new ApiException(ErrorCode.UNAUTHORIZED);
        }
    }
}
