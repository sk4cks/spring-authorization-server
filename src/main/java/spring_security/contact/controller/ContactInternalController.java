package spring_security.contact.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import spring_security.contact.dto.ContactGroupMembersRequest;
import spring_security.contact.dto.ContactGroupRequest;
import spring_security.contact.dto.ContactGroupResponse;
import spring_security.contact.dto.ContactGroupShareRequest;
import spring_security.contact.dto.ContactGroupShareResponse;
import spring_security.contact.dto.ContactRequest;
import spring_security.contact.dto.ContactResponse;
import spring_security.contact.dto.RecipientSuggestItem;
import spring_security.contact.service.ContactService;

import java.util.List;

@RestController
@RequestMapping("/auth/users/{userId}")
@RequiredArgsConstructor
public class ContactInternalController {

    private final ContactService contactService;

    @GetMapping("/contacts")
    public List<ContactResponse> listContacts(
            @PathVariable String userId, @RequestParam(required = false) String q) {
        return contactService.listContacts(userId, q);
    }

    @PostMapping("/contacts")
    public ContactResponse createContact(
            @PathVariable String userId, @Valid @RequestBody ContactRequest request) {
        return contactService.createContact(userId, request);
    }

    @PostMapping("/contacts/{contactId}/delete")
    public ResponseEntity<Void> deleteContact(@PathVariable String userId, @PathVariable Long contactId) {
        contactService.deleteContact(userId, contactId);

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/contacts/suggest")
    public List<RecipientSuggestItem> suggest(
            @PathVariable String userId, @RequestParam(required = false) String q) {
        return contactService.suggest(userId, q);
    }

    @GetMapping("/contact-groups")
    public List<ContactGroupResponse> listGroups(@PathVariable String userId) {
        return contactService.listGroups(userId);
    }

    @PostMapping("/contact-groups")
    public ContactGroupResponse createGroup(
            @PathVariable String userId, @Valid @RequestBody ContactGroupRequest request) {
        return contactService.createGroup(userId, request);
    }

    @PostMapping("/contact-groups/{groupId}/update")
    public ContactGroupResponse renameGroup(
            @PathVariable String userId,
            @PathVariable Long groupId,
            @Valid @RequestBody ContactGroupRequest request) {
        return contactService.renameGroup(userId, groupId, request);
    }

    @PostMapping("/contact-groups/{groupId}/delete")
    public ResponseEntity<Void> deleteGroup(@PathVariable String userId, @PathVariable Long groupId) {
        contactService.deleteGroup(userId, groupId);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/contact-groups/{groupId}/members")
    public ContactGroupResponse replaceMembers(
            @PathVariable String userId,
            @PathVariable Long groupId,
            @Valid @RequestBody ContactGroupMembersRequest request) {
        return contactService.replaceMembers(userId, groupId, request);
    }

    @GetMapping("/contact-groups/{groupId}/shares")
    public List<ContactGroupShareResponse> listShares(
            @PathVariable String userId, @PathVariable Long groupId) {
        return contactService.listShares(userId, groupId);
    }

    @PostMapping("/contact-groups/{groupId}/shares")
    public ContactGroupShareResponse shareGroup(
            @PathVariable String userId,
            @PathVariable Long groupId,
            @Valid @RequestBody ContactGroupShareRequest request) {
        return contactService.shareGroup(userId, groupId, request);
    }

    @PostMapping("/contact-groups/{groupId}/shares/{shareId}/delete")
    public ResponseEntity<Void> revokeShare(
            @PathVariable String userId, @PathVariable Long groupId, @PathVariable Long shareId) {
        contactService.revokeShare(userId, groupId, shareId);

        return ResponseEntity.noContent().build();
    }
}
