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
        this.encryptor = Encryptors.text(secret, saltHex);
    }

    public String encrypt(String plainPassword) {
        return encryptor.encrypt(plainPassword);
    }

    public String decrypt(String encryptedPassword) {
        return encryptor.decrypt(encryptedPassword);
    }
}
