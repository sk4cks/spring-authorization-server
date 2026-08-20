package spring_security.contact.dto;

import spring_security.contact.domain.ContactSharePermission;
import spring_security.contact.domain.MailContactGroupShare;

public record ContactGroupShareResponse(
        Long id, Long groupId, String sharedWithUserId, ContactSharePermission permission) {

    public static ContactGroupShareResponse of(
            MailContactGroupShare share, String sharedWithUserId) {
        return new ContactGroupShareResponse(
                share.getShareSeq(), share.getGroupSeq(), sharedWithUserId, share.getPermission());
    }
}
