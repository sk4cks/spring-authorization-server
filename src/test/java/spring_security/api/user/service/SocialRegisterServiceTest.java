package spring_security.api.user.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import spring_security.api.auth.security.InternalApiKeyVerifier;
import spring_security.api.auth.service.AccessTokenService;
import spring_security.api.common.exception.AppException;
import spring_security.api.common.exception.ErrorCode;
import spring_security.api.user.domain.AuthProvider;
import spring_security.api.user.domain.SysUser;
import spring_security.api.user.dto.SocialRegisterRequest;
import spring_security.api.user.dto.SocialStatusResponse;
import spring_security.api.user.repository.SysUserQueryRepository;
import spring_security.api.user.repository.SysUserRepository;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SocialRegisterServiceTest {

    @Mock private InternalApiKeyVerifier internalApiKeyVerifier;
    @Mock private SysUserRepository sysUserRepository;
    @Mock private SysUserQueryRepository sysUserQueryRepository;
    @Mock private AccessTokenService accessTokenService;

    @InjectMocks private SocialRegisterService socialRegisterService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(socialRegisterService, "mailDomain", "note.local");
    }

    @Test
    void getStatus_returnsRegisteredWhenUserExists() {
        SysUser user = SysUser.createSocial("sk4cks", "sk4cks@note.local", AuthProvider.GOOGLE, "gid", "a@b.com");
        when(sysUserQueryRepository.findByAuthProviderAndExternalId(AuthProvider.GOOGLE, "gid"))
                .thenReturn(Optional.of(user));

        SocialStatusResponse status = socialRegisterService.getStatusForInternal("key", "GOOGLE", "gid");

        assertThat(status.registered()).isTrue();
        assertThat(status.userId()).isEqualTo("sk4cks");
        verify(internalApiKeyVerifier).requireValid("key");
    }

    @Test
    void register_createsSocialUserAndIssuesToken() {
        SocialRegisterRequest request =
                new SocialRegisterRequest("GOOGLE", "gid", "a@b.com", "sk4cks");
        SysUser saved = SysUser.createSocial("sk4cks", "sk4cks@note.local", AuthProvider.GOOGLE, "gid", "a@b.com");
        when(sysUserQueryRepository.existsByAuthProviderAndExternalId(AuthProvider.GOOGLE, "gid"))
                .thenReturn(false);
        when(sysUserQueryRepository.existsByUserId("sk4cks")).thenReturn(false);
        when(sysUserQueryRepository.existsByMailAddress("sk4cks@note.local")).thenReturn(false);
        when(sysUserRepository.save(any(SysUser.class))).thenReturn(saved);
        when(accessTokenService.issueAccessTokenForUser(any(SysUser.class)))
                .thenReturn(Map.of("access_token", "tok", "token_type", "Bearer", "expires_in", 3600));

        Map<String, Object> result = socialRegisterService.registerForInternal("key", request);

        assertThat(result.get("access_token")).isEqualTo("tok");
        assertThat(result.get("userId")).isEqualTo("sk4cks");
        ArgumentCaptor<SysUser> captor = ArgumentCaptor.forClass(SysUser.class);
        verify(sysUserRepository).save(captor.capture());
        assertThat(captor.getValue().getAuthProvider()).isEqualTo(AuthProvider.GOOGLE);
    }

    @Test
    void register_throwsWhenSocialAccountAlreadyRegistered() {
        when(sysUserQueryRepository.existsByAuthProviderAndExternalId(AuthProvider.KAKAO, "1"))
                .thenReturn(true);

        assertThatThrownBy(() -> socialRegisterService.registerForInternal(
                        "key", new SocialRegisterRequest("KAKAO", "1", null, "sk4cks")))
                .isInstanceOf(AppException.class)
                .extracting("errorCode")
                .isEqualTo(ErrorCode.USER_ALREADY_EXISTS);
    }

    @Test
    void register_rejectsInvalidApiKey() {
        doThrow(new AppException(ErrorCode.UNAUTHORIZED))
                .when(internalApiKeyVerifier)
                .requireValid("bad");

        assertThatThrownBy(() -> socialRegisterService.getStatusForInternal("bad", "GOOGLE", "gid"))
                .isInstanceOf(AppException.class);
    }
}
