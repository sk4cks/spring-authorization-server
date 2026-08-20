package spring_security.contact.dto;

import spring_security.contact.domain.MailContact;

public record ContactResponse(Long id, String displayName, String email) {

    public static ContactResponse from(MailContact contact) {
        return new ContactResponse(contact.getContactSeq(), contact.getDisplayName(), contact.getEmail());
    }
}
