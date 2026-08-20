package spring_security.contact.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import spring_security.contact.domain.ContactSharePermission;

public record ContactGroupShareRequest(
        @NotBlank String sharedWithUserId, @NotNull ContactSharePermission permission) {}
