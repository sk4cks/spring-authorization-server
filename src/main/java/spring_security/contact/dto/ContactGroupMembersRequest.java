package spring_security.contact.dto;

import java.util.List;

public record ContactGroupMembersRequest(List<Long> contactIds, List<Long> accountUserSeqs) {}
