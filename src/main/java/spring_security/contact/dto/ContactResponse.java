package spring_security.contact.dto;

import spring_security.contact.domain.MailContact;
import spring_security.user.domain.SysUser;

public record ContactResponse(
        Long id, Long accountUserSeq, String displayName, String email, boolean fromAccount) {

    public static ContactResponse from(MailContact contact) {
        return new ContactResponse(
                contact.getContactSeq(), null, contact.getDisplayName(), contact.getEmail(), false);
    }

    public static ContactResponse fromAccount(SysUser user) {
        return new ContactResponse(null, user.getUserSeq(), user.getUserId(), user.getMailAddress(), true);
    }
}
