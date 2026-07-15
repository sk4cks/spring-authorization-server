package spring_security.mailcow;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Mailcow REST API 클라이언트.
 * <p>
 * 로컬: {@code https://127.0.0.1:8443} + self-signed.<br/>
 * EC2에는 아직 Mailcow 없음 → {@code app.mail.mailcow.enabled=false}.
 */
@Component
@EnableConfigurationProperties(MailcowProperties.class)
public class MailcowClient {

    private static final Logger log = LoggerFactory.getLogger(MailcowClient.class);

    private final RestTemplate mailcowRestTemplate;
    private final MailcowProperties properties;

    public MailcowClient(
            @Qualifier("mailcowRestTemplate") RestTemplate mailcowRestTemplate,
            MailcowProperties properties) {
        this.mailcowRestTemplate = mailcowRestTemplate;
        this.properties = properties;
    }

    /**
     * 메일함 생성. {@code enabled=false} 이면 no-op.
     *
     * @param localPart  userId (@ 앞)
     * @param domain     note.local
     * @param displayName 표시 이름
     * @param password   메일함 로그인 비밀번호 (IMAP/SMTP)
     */
    public void createMailbox(String localPart, String domain, String displayName, String password) {
        if (!properties.enabled()) {
            log.debug("Mailcow disabled — skip mailbox create for {}@{}", localPart, domain);
            return;
        }
        if (!StringUtils.hasText(properties.apiKey()) || !StringUtils.hasText(properties.baseUrl())) {
            throw new AppException(ErrorCode.MAILCOW_ERROR, "Mailcow API is enabled but base-url/api-key missing");
        }

        String url = trimTrailingSlash(properties.baseUrl()) + "/api/v1/add/mailbox";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-API-Key", properties.apiKey());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("local_part", localPart);
        body.put("domain", domain);
        body.put("name", StringUtils.hasText(displayName) ? displayName : localPart);
        body.put("password", password);
        body.put("password2", password);
        body.put("quota", "1024");
        body.put("active", "1");
        body.put("force_pw_update", "0");
        body.put("tls_enforce_in", "0");
        body.put("tls_enforce_out", "0");

        try {
            ResponseEntity<String> response = mailcowRestTemplate.postForEntity(
                    url, new HttpEntity<>(body, headers), String.class);
            String responseBody = response.getBody() != null ? response.getBody() : "";
            if (!response.getStatusCode().is2xxSuccessful() || responseBody.contains("\"type\":\"error\"")) {
                log.error("Mailcow create mailbox failed: status={} body={}", response.getStatusCode(), responseBody);
                throw new AppException(ErrorCode.MAILCOW_ERROR, "Failed to create mailbox: " + localPart + "@" + domain);
            }
            log.info("Mailcow mailbox created: {}@{}", localPart, domain);
        } catch (RestClientException ex) {
            log.error("Mailcow API call failed for {}@{}", localPart, domain, ex);
            throw new AppException(ErrorCode.MAILCOW_ERROR, "Mailcow API unavailable: " + ex.getMessage());
        }
    }

    private static String trimTrailingSlash(String baseUrl) {
        if (baseUrl.endsWith("/")) {
            return baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl;
    }
}
