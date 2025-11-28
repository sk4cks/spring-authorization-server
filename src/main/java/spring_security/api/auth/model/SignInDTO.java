package spring_security.api.auth.model;

import jakarta.validation.constraints.NotBlank;

public record SignInDTO(
    @NotBlank String userId,
    @NotBlank String password
) {}
