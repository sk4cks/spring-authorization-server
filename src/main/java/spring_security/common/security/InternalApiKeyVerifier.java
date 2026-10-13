package spring_security.common.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;

/**
 * BFF가 보내는 {@code X-Internal-Api-Key}와 {@code app.internal-api-key} 비교.
 */
@Component
public class InternalApiKeyVerifier {

    @Value("${app.internal-api-key}")
    private String internalApiKey;

    /** X-Internal-Api-Key와 설정 키 비교. */
    public boolean isValid(String apiKey) {
        // 빈 키는 항상 실패. 타이밍 공격까지는 검사 생략.
        return StringUtils.hasText(apiKey) && apiKey.equals(internalApiKey);
    }

    /** 키가 틀리면 UNAUTHORIZED 예외. */
    public void requireValid(String apiKey) {
        if (!isValid(apiKey)) {
            throw new ApiException(ErrorCode.UNAUTHORIZED);
        }
    }
}
