package spring_security.user.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import spring_security.common.exception.AppException;
import spring_security.common.exception.ErrorCode;
import spring_security.common.exception.GlobalExceptionHandler;
import spring_security.common.security.InternalApiKeyInterceptor;
import spring_security.common.security.InternalApiKeyVerifier;
import spring_security.common.security.InternalApiKeyWebConfig;
import spring_security.user.domain.AuthProvider;
import spring_security.user.domain.UserStatus;
import spring_security.user.dto.MailboxCredentialsResponse;
import spring_security.user.dto.UserResponse;
import spring_security.user.service.RegisterService;
import spring_security.user.service.UserMailboxService;
import spring_security.user.service.UserQueryService;
import spring_security.user.service.UserWithdrawService;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = {RegisterController.class, UserInternalController.class})
@Import({
    GlobalExceptionHandler.class,
    InternalApiKeyWebConfig.class,
    InternalApiKeyInterceptor.class,
    InternalApiKeyVerifier.class
})
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
@TestPropertySource(properties = "app.internal-api-key=dev-internal-key")
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private RegisterService registerService;

    @MockBean
    private UserQueryService userQueryService;

    @MockBean
    private UserWithdrawService userWithdrawService;

    @MockBean
    private UserMailboxService userMailboxService;

    @Test
    void register_returnsCreated() throws Exception {
        when(registerService.register(org.mockito.ArgumentMatchers.any()))
                .thenReturn(new UserResponse(1L, "sk4cks", "sk4cks@note.local", AuthProvider.LOCAL, UserStatus.ACTIVE));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":\"sk4cks\",\"password\":\"1234\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.userId").value("sk4cks"))
                .andExpect(jsonPath("$.mailAddress").value("sk4cks@note.local"));
    }

    @Test
    void register_returnsConflictWhenDuplicate() throws Exception {
        when(registerService.register(org.mockito.ArgumentMatchers.any()))
                .thenThrow(new AppException(ErrorCode.USER_ALREADY_EXISTS, "User already exists: sk4cks"));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"userId\":\"sk4cks\",\"password\":\"1234\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("USER_ALREADY_EXISTS"));
    }

    @Test
    void getUser_returnsUserWhenApiKeyValid() throws Exception {
        when(userQueryService.findByUserId("sk4cks"))
                .thenReturn(new UserResponse(1L, "sk4cks", "sk4cks@note.local", AuthProvider.LOCAL, UserStatus.ACTIVE));

        mockMvc.perform(get("/auth/users/sk4cks").header("X-Internal-Api-Key", "dev-internal-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("sk4cks"));
    }

    @Test
    void getUser_returnsUnauthorizedWhenApiKeyMissing() throws Exception {
        mockMvc.perform(get("/auth/users/sk4cks"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

        verifyNoInteractions(userQueryService);
    }

    @Test
    void withdraw_returnsNoContent() throws Exception {
        mockMvc.perform(
                        post("/auth/users/sk4cks/withdraw").header("X-Internal-Api-Key", "dev-internal-key"))
                .andExpect(status().isNoContent());

        verify(userWithdrawService).withdraw("sk4cks");
    }

    @Test
    void getMailbox_returnsCredentialsWhenApiKeyValid() throws Exception {
        when(userMailboxService.getMailbox("sk4cks"))
                .thenReturn(new MailboxCredentialsResponse(
                        "sk4cks@note.local", "plain", "127.0.0.1", 993, "127.0.0.1", 587));

        mockMvc.perform(get("/auth/users/sk4cks/mailbox").header("X-Internal-Api-Key", "dev-internal-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mailAddress").value("sk4cks@note.local"))
                .andExpect(jsonPath("$.password").value("plain"))
                .andExpect(jsonPath("$.imapPort").value(993));
    }
}
