package spring_security.user.social.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record SocialRegisterRequest(
        @NotBlank String provider,
        @NotBlank String externalId,
        String externalEmail,
        @NotBlank @Size(min = 3, max = 64) @Pattern(regexp = "^[a-zA-Z0-9_]+$") String userId) {}
