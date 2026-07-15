package spring_security.mail;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MailboxPasswordCipherTest {

    @Test
    void encryptDecrypt_roundTrip() {
        MailboxPasswordCipher cipher = new MailboxPasswordCipher(
                "local-dev-mailbox-secret-change-me",
                "a1b2c3d4e5f60718293a4b5c6d7e8f90");

        String encrypted = cipher.encrypt("my-mailbox-password");
        assertThat(encrypted).isNotEqualTo("my-mailbox-password");
        assertThat(cipher.decrypt(encrypted)).isEqualTo("my-mailbox-password");
    }
}
