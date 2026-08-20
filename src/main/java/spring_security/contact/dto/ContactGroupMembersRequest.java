package spring_security.contact.dto;

import jakarta.validation.constraints.NotNull;

import java.util.List;

public record ContactGroupMembersRequest(@NotNull List<Long> contactIds) {}
