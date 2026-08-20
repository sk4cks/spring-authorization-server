package spring_security.contact.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ContactRequest(String displayName, @NotBlank @Email String email) {}
