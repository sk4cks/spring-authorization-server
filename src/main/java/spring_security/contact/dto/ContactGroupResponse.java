package spring_security.contact.dto;

import spring_security.contact.domain.ContactSharePermission;
import spring_security.contact.domain.MailContactGroup;

import java.util.List;

public record ContactGroupResponse(
        Long id,
        String name,
        boolean owned,
        ContactSharePermission permission,
        List<ContactResponse> members) {

    public static ContactGroupResponse of(
            MailContactGroup group,
            boolean owned,
            ContactSharePermission permission,
            List<ContactResponse> members) {
        return new ContactGroupResponse(
                group.getGroupSeq(), group.getName(), owned, permission, members);
    }
}
