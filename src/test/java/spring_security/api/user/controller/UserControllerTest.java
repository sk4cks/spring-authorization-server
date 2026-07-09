package spring_security.api.user.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import spring_security.api.common.exception.AppException;
import spring_security.api.common.exception.ErrorCode;
import spring_security.api.common.exception.GlobalExceptionHandler;
import spring_security.api.user.domain.AuthProvider;
import spring_security.api.user.domain.UserStatus;
import spring_security.api.user.dto.UserResponse;
import spring_security.api.user.service.RegisterService;
import spring_security.api.user.service.UserQueryService;
import spring_security.api.user.service.UserWithdrawService;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = {RegisterController.class, UserInternalController.class})
@Import(GlobalExceptionHandler.class)
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private RegisterService registerService;

    @MockBean
    private UserQueryService userQueryService;

    @MockBean
    private UserWithdrawService userWithdrawService;

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
        when(userQueryService.findByUserIdForInternal("dev-internal-key", "sk4cks"))
                .thenReturn(new UserResponse(1L, "sk4cks", "sk4cks@note.local", AuthProvider.LOCAL, UserStatus.ACTIVE));

        mockMvc.perform(get("/auth/users/sk4cks").header("X-Internal-Api-Key", "dev-internal-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("sk4cks"));
    }

    @Test
    void getUser_returnsUnauthorizedWhenApiKeyMissing() throws Exception {
        when(userQueryService.findByUserIdForInternal(eq(null), eq("sk4cks")))
                .thenThrow(new AppException(ErrorCode.UNAUTHORIZED));

        mockMvc.perform(get("/auth/users/sk4cks"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void withdraw_returnsNoContent() throws Exception {
        mockMvc.perform(
                        post("/auth/users/sk4cks/withdraw").header("X-Internal-Api-Key", "dev-internal-key"))
                .andExpect(status().isNoContent());

        verify(userWithdrawService).withdrawForInternal("dev-internal-key", "sk4cks");
    }
}
