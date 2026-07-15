package spring_security.user.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;
import spring_security.mail.MailboxPasswordCipher;
import spring_security.mailcow.MailcowProperties;
import spring_security.user.domain.SysUser;
import spring_security.user.dto.MailboxCredentialsResponse;
import spring_security.user.repository.SysUserQueryRepository;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserMailboxServiceTest {

    @Mock private SysUserQueryRepository sysUserQueryRepository;
    @Mock private MailboxPasswordCipher mailboxPasswordCipher;

    private UserMailboxService userMailboxService;

    @BeforeEach
    void setUp() {
        MailcowProperties properties = new MailcowProperties(
                true, "https://127.0.0.1:8443", "key", "127.0.0.1", 993, "127.0.0.1", 587);
        userMailboxService = new UserMailboxService(
                sysUserQueryRepository, mailboxPasswordCipher, properties);
    }

    @Test
    void getMailbox_decryptsPasswordAndReturnsHosts() {
        SysUser user = SysUser.createLocal("sk4cks", "sk4cks@note.local", "{bcrypt}hash");
        user.assignMailboxPasswordEnc("enc-pwd");
        when(sysUserQueryRepository.findByUserId("sk4cks")).thenReturn(Optional.of(user));
        when(mailboxPasswordCipher.decrypt("enc-pwd")).thenReturn("plain-pwd");

        MailboxCredentialsResponse response = userMailboxService.getMailbox("sk4cks");

        assertThat(response.mailAddress()).isEqualTo("sk4cks@note.local");
        assertThat(response.password()).isEqualTo("plain-pwd");
        assertThat(response.imapHost()).isEqualTo("127.0.0.1");
        assertThat(response.imapPort()).isEqualTo(993);
        assertThat(response.smtpHost()).isEqualTo("127.0.0.1");
        assertThat(response.smtpPort()).isEqualTo(587);
    }

    @Test
    void getMailbox_throwsWhenUserMissing() {
        when(sysUserQueryRepository.findByUserId("missing")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userMailboxService.getMailbox("missing"))
                .isInstanceOf(AppException.class)
                .extracting("errorCode")
                .isEqualTo(ErrorCode.USER_NOT_FOUND);
    }

    @Test
    void getMailbox_throwsWhenMailboxPasswordMissing() {
        SysUser user = SysUser.createLocal("sk4cks", "sk4cks@note.local", "{bcrypt}hash");
        when(sysUserQueryRepository.findByUserId("sk4cks")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> userMailboxService.getMailbox("sk4cks"))
                .isInstanceOf(AppException.class)
                .extracting("errorCode")
                .isEqualTo(ErrorCode.USER_NOT_FOUND);
    }
}
