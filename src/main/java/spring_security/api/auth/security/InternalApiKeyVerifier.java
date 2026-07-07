package spring_security.api.auth.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import spring_security.api.common.exception.AppException;
import spring_security.api.common.exception.ErrorCode;

@Component
public class InternalApiKeyVerifier {

    @Value("${app.internal-api-key}")
    private String internalApiKey;

    public boolean isValid(String apiKey) {
        return StringUtils.hasText(apiKey) && apiKey.equals(internalApiKey);
    }

    public void requireValid(String apiKey) {
        if (!isValid(apiKey)) {
            throw new AppException(ErrorCode.UNAUTHORIZED);
        }
    }
}
