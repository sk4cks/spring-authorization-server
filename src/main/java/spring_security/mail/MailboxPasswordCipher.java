package spring_security.mail;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Mailcow 메일함 평문 비밀번호를 DB에 넣을 때 AES 암호화.
 * Spring {@link Encryptors#text(CharSequence, CharSequence)} — password + hex salt.
 */
@Component
public class MailboxPasswordCipher {

    private final TextEncryptor encryptor;

    public MailboxPasswordCipher(
            @Value("${app.mail.mailbox-secret}") String secret,
            @Value("${app.mail.mailbox-salt}") String saltHex) {
        if (!StringUtils.hasText(secret) || !StringUtils.hasText(saltHex)) {
            throw new IllegalStateException("app.mail.mailbox-secret and mailbox-salt are required");
        }

        // salt는 hex 문자열이어야 한다. 기동 시 한 번만 만든다.
        this.encryptor = Encryptors.text(secret, saltHex);
    }

    public String encrypt(String plainPassword) {
        // SYS_USER.MAILBOX_PASSWORD_ENC에 넣을 암호문.
        return encryptor.encrypt(plainPassword);
    }

    public String decrypt(String encryptedPassword) {
        // BFF IMAP LOGIN에 넘길 평문. 내부 API에서만 호출한다.
        return encryptor.decrypt(encryptedPassword);
    }
}
