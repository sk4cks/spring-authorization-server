package spring_security.mailcow;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.mail.mailcow")
public record MailcowProperties(
        boolean enabled,
        String baseUrl,
        String apiKey,
        String imapHost,
        int imapPort,
        String smtpHost,
        int smtpPort) {

    public MailcowProperties {
        if (imapHost == null || imapHost.isBlank()) {
            imapHost = "127.0.0.1";
        }
        if (imapPort == 0) {
            imapPort = 993;
        }
        if (smtpHost == null || smtpHost.isBlank()) {
            smtpHost = "127.0.0.1";
        }
        if (smtpPort == 0) {
            smtpPort = 587;
        }
    }
}
