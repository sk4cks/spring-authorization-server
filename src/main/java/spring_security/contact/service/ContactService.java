package spring_security.contact.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;
import spring_security.contact.domain.ContactSharePermission;
import spring_security.contact.domain.MailContact;
import spring_security.contact.domain.MailContactGroup;
import spring_security.contact.domain.MailContactGroupMember;
import spring_security.contact.domain.MailContactGroupShare;
import spring_security.contact.dto.ContactGroupMembersRequest;
import spring_security.contact.dto.ContactGroupRequest;
import spring_security.contact.dto.ContactGroupResponse;
import spring_security.contact.dto.ContactGroupShareRequest;
import spring_security.contact.dto.ContactGroupShareResponse;
import spring_security.contact.dto.ContactRequest;
import spring_security.contact.dto.ContactResponse;
import spring_security.contact.dto.RecipientSuggestItem;
import spring_security.contact.repository.MailContactGroupMemberRepository;
import spring_security.contact.repository.MailContactGroupRepository;
import spring_security.contact.repository.MailContactGroupShareRepository;
import spring_security.contact.repository.MailContactRepository;
import spring_security.user.domain.SysUser;
import spring_security.user.repository.SysUserQueryRepository;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ContactService {

    private final SysUserQueryRepository sysUserQueryRepository;
    private final MailContactRepository contactRepository;
    private final MailContactGroupRepository groupRepository;
    private final MailContactGroupMemberRepository memberRepository;
    private final MailContactGroupShareRepository shareRepository;

    @Transactional(readOnly = true)
    public List<ContactResponse> listContacts(String userId, String q) {
        SysUser user = requireUser(userId);
        List<MailContact> contacts = StringUtils.hasText(q)
                ? contactRepository.searchActiveByUserSeq(user.getUserSeq(), q.trim())
                : contactRepository.findActiveByUserSeq(user.getUserSeq());

        return contacts.stream().map(ContactResponse::from).toList();
    }

    @Transactional
    public ContactResponse createContact(String userId, ContactRequest request) {
        SysUser user = requireUser(userId);
        String email = request.email().trim();
        if (contactRepository.existsActiveEmail(user.getUserSeq(), email)) {
            throw new ApiException(ErrorCode.CONTACT_ALREADY_EXISTS);
        }
        MailContact saved = contactRepository.save(
                MailContact.create(user.getUserSeq(), blankToNull(request.displayName()), email));

        return ContactResponse.from(saved);
    }

    @Transactional
    public ContactResponse updateContact(String userId, Long contactId, ContactRequest request) {
        SysUser user = requireUser(userId);
        MailContact contact = contactRepository
                .findActiveBySeqAndUser(contactId, user.getUserSeq())
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_NOT_FOUND));
        String email = request.email().trim();
        if (!contact.getEmail().equalsIgnoreCase(email)
                && contactRepository.existsActiveEmail(user.getUserSeq(), email)) {
            throw new ApiException(ErrorCode.CONTACT_ALREADY_EXISTS);
        }
        contact.update(blankToNull(request.displayName()), email, user.getUserSeq());

        return ContactResponse.from(contact);
    }

    @Transactional
    public void deleteContact(String userId, Long contactId) {
        SysUser user = requireUser(userId);
        MailContact contact = contactRepository
                .findActiveBySeqAndUser(contactId, user.getUserSeq())
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_NOT_FOUND));
        contact.softDelete(user.getUserSeq());
    }

    @Transactional(readOnly = true)
    public List<ContactGroupResponse> listGroups(String userId) {
        SysUser user = requireUser(userId);
        return groupRepository.findAccessibleByUser(user.getUserSeq()).stream()
                .map(group -> toGroupResponse(group, user.getUserSeq()))
                .toList();
    }

    @Transactional
    public ContactGroupResponse createGroup(String userId, ContactGroupRequest request) {
        SysUser user = requireUser(userId);
        MailContactGroup saved =
                groupRepository.save(MailContactGroup.create(user.getUserSeq(), request.name()));

        return ContactGroupResponse.of(saved, true, ContactSharePermission.WRITE, List.of());
    }

    @Transactional
    public ContactGroupResponse renameGroup(String userId, Long groupId, ContactGroupRequest request) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        requireWrite(group, user.getUserSeq());
        group.rename(request.name(), user.getUserSeq());

        return toGroupResponse(group, user.getUserSeq());
    }

    @Transactional
    public void deleteGroup(String userId, Long groupId) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        if (!Objects.equals(group.getOwnerUserSeq(), user.getUserSeq())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        group.softDelete(user.getUserSeq());
        for (MailContactGroupShare share : shareRepository.findActiveByGroupSeq(groupId)) {
            share.softDelete(user.getUserSeq());
        }
    }

    @Transactional
    public ContactGroupResponse replaceMembers(
            String userId, Long groupId, ContactGroupMembersRequest request) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        requireWrite(group, user.getUserSeq());
        Long ownerSeq = group.getOwnerUserSeq();
        List<Long> ids = request.contactIds() == null ? List.of() : request.contactIds();
        List<MailContact> contacts =
                ids.isEmpty() ? List.of() : contactRepository.findActiveBySeqsAndUser(ids, ownerSeq);
        if (contacts.size() != ids.stream().distinct().count()) {
            throw new ApiException(ErrorCode.CONTACT_NOT_FOUND, "Group members must be owner's contacts");
        }
        memberRepository.deleteByGroupSeq(groupId);
        for (MailContact contact : contacts) {
            memberRepository.save(MailContactGroupMember.of(groupId, contact.getContactSeq()));
        }

        return toGroupResponse(group, user.getUserSeq());
    }

    @Transactional(readOnly = true)
    public List<ContactGroupShareResponse> listShares(String userId, Long groupId) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        if (!Objects.equals(group.getOwnerUserSeq(), user.getUserSeq())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }

        return shareRepository.findActiveByGroupSeq(groupId).stream()
                .map(share -> ContactGroupShareResponse.of(
                        share,
                        sysUserQueryRepository
                                .findByUserSeq(share.getSharedWithUserSeq())
                                .map(SysUser::getUserId)
                                .orElse("")))
                .toList();
    }

    @Transactional
    public ContactGroupShareResponse shareGroup(
            String userId, Long groupId, ContactGroupShareRequest request) {
        SysUser owner = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        if (!Objects.equals(group.getOwnerUserSeq(), owner.getUserSeq())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        SysUser target = requireUser(request.sharedWithUserId());
        if (Objects.equals(target.getUserSeq(), owner.getUserSeq())) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "Cannot share group with yourself");
        }
        MailContactGroupShare existing =
                shareRepository.findActive(groupId, target.getUserSeq()).orElse(null);
        if (existing != null) {
            existing.updatePermission(request.permission(), owner.getUserSeq());
            return ContactGroupShareResponse.of(existing, target.getUserId());
        }
        MailContactGroupShare saved = shareRepository.save(MailContactGroupShare.create(
                groupId, target.getUserSeq(), request.permission(), owner.getUserSeq()));

        return ContactGroupShareResponse.of(saved, target.getUserId());
    }

    @Transactional
    public void revokeShare(String userId, Long groupId, Long shareId) {
        SysUser owner = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        if (!Objects.equals(group.getOwnerUserSeq(), owner.getUserSeq())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        MailContactGroupShare share = shareRepository
                .findActiveBySeqAndGroup(shareId, groupId)
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_SHARE_NOT_FOUND));
        share.softDelete(owner.getUserSeq());
    }

    @Transactional(readOnly = true)
    public List<RecipientSuggestItem> suggest(String userId, String q) {
        SysUser user = requireUser(userId);
        String query = q == null ? "" : q.trim();
        List<RecipientSuggestItem> result = new ArrayList<>();

        List<MailContactGroup> groups = StringUtils.hasText(query)
                ? groupRepository.searchAccessibleByUser(user.getUserSeq(), query)
                : groupRepository.findAccessibleByUser(user.getUserSeq());
        for (MailContactGroup group : groups) {
            List<String> emails = memberEmails(group.getGroupSeq());
            if (!emails.isEmpty() || StringUtils.hasText(query)) {
                result.add(RecipientSuggestItem.group(group.getGroupSeq(), group.getName(), emails));
            }
        }

        Map<String, ContactResponse> byEmail = new LinkedHashMap<>();
        List<MailContact> own = StringUtils.hasText(query)
                ? contactRepository.searchActiveByUserSeq(user.getUserSeq(), query)
                : contactRepository.findActiveByUserSeq(user.getUserSeq());
        for (MailContact contact : own) {
            byEmail.putIfAbsent(contact.getEmail().toLowerCase(Locale.ROOT), ContactResponse.from(contact));
        }

        List<Long> sharedGroupIds = groupRepository.findAccessibleByUser(user.getUserSeq()).stream()
                .filter(g -> !Objects.equals(g.getOwnerUserSeq(), user.getUserSeq()))
                .map(MailContactGroup::getGroupSeq)
                .toList();
        if (!sharedGroupIds.isEmpty()) {
            List<Long> contactIds = memberRepository.findContactSeqsByGroupSeqs(sharedGroupIds);
            if (!contactIds.isEmpty()) {
                for (MailContact contact : contactRepository.findActiveBySeqs(contactIds)) {
                    if (StringUtils.hasText(query)) {
                        String hay = ((contact.getDisplayName() == null ? "" : contact.getDisplayName())
                                        + " "
                                        + contact.getEmail())
                                .toLowerCase(Locale.ROOT);
                        if (!hay.contains(query.toLowerCase(Locale.ROOT))) {
                            continue;
                        }
                    }
                    byEmail.putIfAbsent(
                            contact.getEmail().toLowerCase(Locale.ROOT), ContactResponse.from(contact));
                }
            }
        }

        for (ContactResponse contact : byEmail.values()) {
            result.add(RecipientSuggestItem.contact(contact.id(), contact.displayName(), contact.email()));
        }

        return result.stream().limit(30).toList();
    }

    private ContactGroupResponse toGroupResponse(MailContactGroup group, Long viewerUserSeq) {
        boolean owned = Objects.equals(group.getOwnerUserSeq(), viewerUserSeq);
        ContactSharePermission permission = owned
                ? ContactSharePermission.WRITE
                : shareRepository
                        .findActive(group.getGroupSeq(), viewerUserSeq)
                        .map(MailContactGroupShare::getPermission)
                        .orElse(ContactSharePermission.READ);
        List<Long> contactIds = memberRepository.findContactSeqsByGroupSeq(group.getGroupSeq());
        List<ContactResponse> members = contactIds.isEmpty()
                ? List.of()
                : contactRepository.findActiveBySeqs(contactIds).stream()
                        .map(ContactResponse::from)
                        .toList();

        return ContactGroupResponse.of(group, owned, permission, members);
    }

    private List<String> memberEmails(Long groupSeq) {
        List<Long> ids = memberRepository.findContactSeqsByGroupSeq(groupSeq);
        if (ids.isEmpty()) {
            return List.of();
        }

        return contactRepository.findActiveBySeqs(ids).stream()
                .map(MailContact::getEmail)
                .collect(Collectors.toList());
    }

    private void requireWrite(MailContactGroup group, Long userSeq) {
        if (Objects.equals(group.getOwnerUserSeq(), userSeq)) {
            return;
        }
        ContactSharePermission permission = shareRepository
                .findActive(group.getGroupSeq(), userSeq)
                .map(MailContactGroupShare::getPermission)
                .orElse(null);
        if (permission != ContactSharePermission.WRITE) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
    }

    private MailContactGroup requireGroup(Long groupId) {
        return groupRepository
                .findActiveBySeq(groupId)
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_GROUP_NOT_FOUND));
    }

    private SysUser requireUser(String userId) {
        return sysUserQueryRepository
                .findByUserId(userId)
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND, "User not found: " + userId));
    }

    private static String blankToNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}
