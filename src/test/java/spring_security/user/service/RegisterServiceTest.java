package spring_security.user.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;
import spring_security.mail.MailboxPasswordCipher;
import spring_security.mailcow.MailcowClient;
import spring_security.user.domain.AuthProvider;
import spring_security.user.domain.SysUser;
import spring_security.user.domain.UserStatus;
import spring_security.user.dto.RegisterRequest;
import spring_security.user.dto.UserResponse;
import spring_security.user.repository.SysUserQueryRepository;
import spring_security.user.repository.SysUserRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RegisterServiceTest {

  @Mock
  private SysUserRepository sysUserRepository;

  @Mock
  private SysUserQueryRepository sysUserQueryRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private MailcowClient mailcowClient;

  @Mock
  private MailboxPasswordCipher mailboxPasswordCipher;

  private RegisterService registerService;

  @BeforeEach
  void setUp() {
    registerService = new RegisterService(
            sysUserRepository, sysUserQueryRepository, passwordEncoder, mailcowClient, mailboxPasswordCipher);
    setMailDomain("note.local");
  }

  @Test
  void register_createsLocalUser() {
    when(sysUserQueryRepository.existsByUserId("sk4cks")).thenReturn(false);
    when(sysUserQueryRepository.existsByMailAddress("sk4cks@note.local")).thenReturn(false);
    when(passwordEncoder.encode("1234")).thenReturn("{bcrypt}hash");
    when(mailboxPasswordCipher.encrypt("1234")).thenReturn("enc-1234");
    when(sysUserRepository.save(any(SysUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

    UserResponse response = registerService.register(new RegisterRequest("sk4cks", "1234"));

    assertThat(response.userId()).isEqualTo("sk4cks");
    assertThat(response.mailAddress()).isEqualTo("sk4cks@note.local");
    assertThat(response.authProvider()).isEqualTo(AuthProvider.LOCAL);
    assertThat(response.status()).isEqualTo(UserStatus.ACTIVE);

    ArgumentCaptor<SysUser> captor = ArgumentCaptor.forClass(SysUser.class);
    verify(sysUserRepository).save(captor.capture());
    assertThat(captor.getValue().getPasswordHash()).isEqualTo("{bcrypt}hash");
    assertThat(captor.getValue().getMailboxPasswordEnc()).isEqualTo("enc-1234");
    verify(mailcowClient).createMailbox(eq("sk4cks"), eq("note.local"), eq("sk4cks"), eq("1234"));
    verify(mailboxPasswordCipher).encrypt("1234");
  }

    @Test
    void register_throwsWhenUserIdExists() {
        when(sysUserQueryRepository.existsByUserId("sk4cks")).thenReturn(true);

        assertThatThrownBy(() -> registerService.register(new RegisterRequest("sk4cks", "1234")))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.USER_ALREADY_EXISTS));

        verify(sysUserRepository, never()).save(any());
    }

    private void setMailDomain(String domain) {
        try {
            var field = RegisterService.class.getDeclaredField("mailDomain");
            field.setAccessible(true);
            field.set(registerService, domain);
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
