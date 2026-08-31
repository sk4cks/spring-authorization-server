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
import spring_security.contact.dto.ContactDto;
import spring_security.contact.dto.ContactGroupDto;
import spring_security.contact.dto.ContactShareDto;
import spring_security.contact.dto.RecipientSuggestItem;
import spring_security.contact.service.ContactService;

import java.util.List;

/**
 * BFF 전용 주소록 API. 프론트는 호출하지 않고 {@code AuthServerClient}가 API key로 붙는다.
 * 경로의 {@code userId}는 JWT subject와 같은 로그인 사용자다.
 */
@RestController
@RequestMapping("/auth/users/{userId}")
@RequiredArgsConstructor
public class ContactInternalController {

    private final ContactService contactService;

    /**
     * 주소록 목록. 가입된 모든 SYS_USER(메일 있는 계정) + 이 사용자의 MAIL_CONTACT.
     * 같은 이메일이 둘 다 있으면 계정만 남긴다. {@code q}가 있으면 이름/이메일 한글 매칭으로 거른다.
     */
    @GetMapping("/contacts")
    public List<ContactDto.Response> listContacts(
            @PathVariable String userId, @RequestParam(required = false) String q) {
        return contactService.listContacts(userId, q);
    }

    /**
     * 개인 연락처 한 건 INSERT. 이미 SYS_USER 메일이거나 내 주소록에 같은 이메일이 있으면 409.
     */
    @PostMapping("/contacts")
    public ContactDto.Response createContact(
            @PathVariable String userId, @Valid @RequestBody ContactDto.Request request) {
        return contactService.createContact(userId, request);
    }

    /**
     * 내 MAIL_CONTACT 한 건 soft delete. 가입 계정과 이메일이 같으면 지우지 않는다.
     */
    @PostMapping("/contacts/{contactId}/delete")
    public ResponseEntity<Void> deleteContact(@PathVariable String userId, @PathVariable Long contactId) {
        contactService.deleteContact(userId, contactId);

        return ResponseEntity.noContent().build();
    }

    /**
     * 메일 수신자 자동완성. 접근 가능한 그룹(멤버 이메일 포함) + 연락처.
     * BFF {@code /mail/recipients/suggest}가 여기 결과와 메일 히스토리를 합친다.
     */
    @GetMapping("/contacts/suggest")
    public List<RecipientSuggestItem> suggest(
            @PathVariable String userId, @RequestParam(required = false) String q) {
        return contactService.suggest(userId, q);
    }


    /**
     * 내가 만든 그룹 + 남이 공유해 준 그룹. 각 그룹에 멤버·권한·소유자 id를 붙인다.
     */
    @GetMapping("/contact-groups")
    public List<ContactGroupDto.Response> listGroups(@PathVariable String userId) {
        return contactService.listGroups(userId);
    }

    /**
     * 빈 그룹 생성. 호출자가 소유자고 permission은 WRITE, 멤버는 없다.
     */
    @PostMapping("/contact-groups")
    public ContactGroupDto.Response createGroup(
            @PathVariable String userId, @Valid @RequestBody ContactGroupDto.Request request) {
        return contactService.createGroup(userId, request);
    }

    /**
     * 그룹 이름 변경. 소유자만 가능하다. 공유받은 WRITE라도 이름은 못 바꾼다.
     */
    @PostMapping("/contact-groups/{groupId}/update")
    public ContactGroupDto.Response renameGroup(
            @PathVariable String userId,
            @PathVariable Long groupId,
            @Valid @RequestBody ContactGroupDto.Request request) {
        return contactService.renameGroup(userId, groupId, request);
    }

    /**
     * 그룹 soft delete. 소유자만. 이 그룹의 활성 공유 행도 같이 비활성화한다.
     */
    @PostMapping("/contact-groups/{groupId}/delete")
    public ResponseEntity<Void> deleteGroup(@PathVariable String userId, @PathVariable Long groupId) {
        contactService.deleteGroup(userId, groupId);

        return ResponseEntity.noContent().build();
    }

    /**
     * 그룹 멤버를 요청 body 그대로 갈아끼운다(부분 수정 아님).
     * 소유자 또는 WRITE 공유자. 연락처 id는 소유자 주소록 행으로 맞추고, 계정은 SYS_USER seq로 넣는다.
     */
    @PostMapping("/contact-groups/{groupId}/members")
    public ContactGroupDto.Response replaceMembers(
            @PathVariable String userId,
            @PathVariable Long groupId,
            @Valid @RequestBody ContactGroupDto.MembersRequest request) {
        return contactService.replaceMembers(userId, groupId, request);
    }


    /**
     * 이 그룹을 누구에게 어떤 권한으로 공유했는지 목록. 소유자 또는 공유받은 사람만 본다.
     */
    @GetMapping("/contact-groups/{groupId}/shares")
    public List<ContactShareDto.Response> listShares(
            @PathVariable String userId, @PathVariable Long groupId) {
        return contactService.listShares(userId, groupId);
    }

    /**
     * 다른 사용자에게 그룹을 공유하거나, 이미 있으면 권한만 갱신.
     * 소유자/WRITE만. 본인이나 그룹 소유자에게는 공유하지 않는다.
     */
    @PostMapping("/contact-groups/{groupId}/shares")
    public ContactShareDto.Response shareGroup(
            @PathVariable String userId,
            @PathVariable Long groupId,
            @Valid @RequestBody ContactShareDto.Request request) {
        return contactService.shareGroup(userId, groupId, request);
    }

    /**
     * 공유 한 건 soft delete. 공유받은 본인은 자기 것만, 그 외는 WRITE(또는 소유자)만 끊을 수 있다.
     */
    @PostMapping("/contact-groups/{groupId}/shares/{shareId}/delete")
    public ResponseEntity<Void> revokeShare(
            @PathVariable String userId, @PathVariable Long groupId, @PathVariable Long shareId) {
        contactService.revokeShare(userId, groupId, shareId);

        return ResponseEntity.noContent().build();
    }
}
