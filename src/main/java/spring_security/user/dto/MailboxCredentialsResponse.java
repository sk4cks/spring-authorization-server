package spring_security.user.dto;

public record MailboxCredentialsResponse(
        String mailAddress,
        String password,
        String imapHost,
        int imapPort,
        String smtpHost,
        int smtpPort) {}
