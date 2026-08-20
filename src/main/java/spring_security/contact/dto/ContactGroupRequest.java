package spring_security.contact.dto;

import jakarta.validation.constraints.NotBlank;

public record ContactGroupRequest(@NotBlank String name) {}
