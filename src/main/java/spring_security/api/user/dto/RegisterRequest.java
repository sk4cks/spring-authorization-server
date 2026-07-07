package spring_security.api.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank
        @Size(min = 3, max = 64)
        @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "userId는 영문, 숫자, 밑줄만 사용할 수 있습니다")
        String userId,
        @NotBlank
        @Size(min = 4, max = 100)
        String password
) {}
