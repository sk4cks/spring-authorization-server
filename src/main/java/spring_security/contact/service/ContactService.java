package spring_security.contact.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import spring_security.common.exception.ApiException;
import spring_security.common.exception.ErrorCode;
import spring_security.common.util.KoreanTextMatcher;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
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
        return collectContacts(requireUser(userId), q == null ? "" : q.trim());
    }

    @Transactional
    public ContactResponse createContact(String userId, ContactRequest request) {
        SysUser user = requireUser(userId);
        String email = request.email().trim();
        if (sysUserQueryRepository.existsActiveMailIgnoreCase(email)
                || contactRepository.existsActiveEmail(user.getUserSeq(), email)) {
            throw new ApiException(ErrorCode.CONTACT_ALREADY_EXISTS);
        }
        MailContact saved = contactRepository.save(
                MailContact.create(user.getUserSeq(), blankToNull(request.displayName()), email));

        return ContactResponse.from(saved);
    }

    @Transactional
    public void deleteContact(String userId, Long contactId) {
        SysUser user = requireUser(userId);
        MailContact contact = contactRepository
                .findActiveBySeqAndUser(contactId, user.getUserSeq())
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_NOT_FOUND));
        if (sysUserQueryRepository.existsActiveMailIgnoreCase(contact.getEmail())) {
            throw new ApiException(ErrorCode.FORBIDDEN, "가입된 계정 연락처는 삭제할 수 없습니다.");
        }
        contact.softDelete(user.getUserSeq());
    }

    @Transactional(readOnly = true)
    public List<ContactGroupResponse> listGroups(String userId) {
        SysUser user = requireUser(userId);
        Set<String> directoryEmails = accountEmails();
        return groupRepository.findAccessibleByUser(user.getUserSeq()).stream()
                .map(group -> toGroupResponse(group, user.getUserSeq(), directoryEmails))
                .toList();
    }

    @Transactional
    public ContactGroupResponse createGroup(String userId, ContactGroupRequest request) {
        SysUser user = requireUser(userId);
        MailContactGroup saved =
                groupRepository.save(MailContactGroup.create(user.getUserSeq(), request.name()));

        return ContactGroupResponse.of(
                saved, true, ContactSharePermission.WRITE, user.getUserId(), null, List.of());
    }

    @Transactional
    public ContactGroupResponse renameGroup(String userId, Long groupId, ContactGroupRequest request) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        if (!Objects.equals(group.getOwnerUserSeq(), user.getUserSeq())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        group.rename(request.name(), user.getUserSeq());

        return toGroupResponse(group, user.getUserSeq(), accountEmails());
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
        List<Long> contactIds = distinct(request == null ? null : request.contactIds());
        List<Long> accountUserSeqs = distinct(request == null ? null : request.accountUserSeqs());
        LinkedHashSet<Long> accountSeqs = new LinkedHashSet<>(accountUserSeqs);
        List<MailContact> ownerContacts = resolveMembersToOwner(contactIds, ownerSeq, user.getUserSeq(), accountSeqs);
        List<SysUser> accounts = sysUserQueryRepository.findActiveByUserSeqs(accountSeqs);
        if (accounts.size() != accountSeqs.size()) {
            throw new ApiException(ErrorCode.USER_NOT_FOUND, "Group members must be registered accounts");
        }
        memberRepository.deleteByGroupSeq(groupId);
        for (MailContact contact : ownerContacts) {
            memberRepository.save(MailContactGroupMember.ofContact(groupId, contact.getContactSeq()));
        }
        for (SysUser account : accounts) {
            memberRepository.save(MailContactGroupMember.ofAccount(groupId, account.getUserSeq()));
        }

        return toGroupResponse(group, user.getUserSeq(), accountEmails());
    }

    @Transactional(readOnly = true)
    public List<ContactGroupShareResponse> listShares(String userId, Long groupId) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        requireAccess(group, user.getUserSeq());

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
        SysUser actor = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        requireWrite(group, actor.getUserSeq());
        SysUser target = requireUser(request.sharedWithUserId());
        if (Objects.equals(target.getUserSeq(), actor.getUserSeq())
                || Objects.equals(target.getUserSeq(), group.getOwnerUserSeq())) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "Cannot share group with yourself");
        }
        MailContactGroupShare existing =
                shareRepository.findActive(groupId, target.getUserSeq()).orElse(null);
        if (existing != null) {
            existing.updatePermission(request.permission(), actor.getUserSeq());
            return ContactGroupShareResponse.of(existing, target.getUserId());
        }
        MailContactGroupShare saved = shareRepository.save(MailContactGroupShare.create(
                groupId, target.getUserSeq(), request.permission(), actor.getUserSeq()));

        return ContactGroupShareResponse.of(saved, target.getUserId());
    }

    @Transactional
    public void revokeShare(String userId, Long groupId, Long shareId) {
        SysUser actor = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        MailContactGroupShare share = shareRepository
                .findActiveBySeqAndGroup(shareId, groupId)
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_SHARE_NOT_FOUND));
        boolean ownShare = Objects.equals(share.getSharedWithUserSeq(), actor.getUserSeq());
        if (!ownShare) {
            requireWrite(group, actor.getUserSeq());
        }
        share.softDelete(actor.getUserSeq());
    }

    @Transactional(readOnly = true)
    public List<RecipientSuggestItem> suggest(String userId, String q) {
        SysUser user = requireUser(userId);
        String query = q == null ? "" : q.trim();
        List<RecipientSuggestItem> result = new ArrayList<>();
        List<MailContactGroup> accessible = groupRepository.findAccessibleByUser(user.getUserSeq());

        for (MailContactGroup group : accessible) {
            if (!KoreanTextMatcher.matches(query, group.getName())) {
                continue;
            }
            List<String> emails = memberEmails(group.getGroupSeq());
            if (!emails.isEmpty() || StringUtils.hasText(query)) {
                result.add(RecipientSuggestItem.group(group.getGroupSeq(), group.getName(), emails));
            }
        }

        Map<String, ContactResponse> byEmail = new LinkedHashMap<>();
        for (ContactResponse contact : collectContacts(user, query)) {
            byEmail.put(contact.email().toLowerCase(Locale.ROOT), contact);
        }

        List<Long> sharedGroupIds = accessible.stream()
                .filter(g -> !Objects.equals(g.getOwnerUserSeq(), user.getUserSeq()))
                .map(MailContactGroup::getGroupSeq)
                .toList();
        if (!sharedGroupIds.isEmpty()) {
            List<Long> contactIds = memberRepository.findContactSeqsByGroupSeqs(sharedGroupIds);
            if (!contactIds.isEmpty()) {
                for (MailContact contact : contactRepository.findActiveBySeqs(contactIds)) {
                    if (!KoreanTextMatcher.matches(query, contact.getDisplayName(), contact.getEmail())) {
                        continue;
                    }
                    byEmail.putIfAbsent(
                            contact.getEmail().toLowerCase(Locale.ROOT), ContactResponse.from(contact));
                }
            }
        }

        for (ContactResponse contact : byEmail.values()) {
            Long suggestId = contact.fromAccount() ? contact.accountUserSeq() : contact.id();
            result.add(RecipientSuggestItem.contact(suggestId, contact.displayName(), contact.email()));
        }

        return result.stream().limit(30).toList();
    }

    private List<ContactResponse> collectContacts(SysUser user, String query) {
        List<SysUser> accounts = sysUserQueryRepository.findAllActive();
        Set<String> directoryEmails = accountEmails(accounts);
        List<ContactResponse> result = new ArrayList<>();
        for (SysUser account : accounts) {
            if (!StringUtils.hasText(account.getMailAddress())) {
                continue;
            }
            if (!KoreanTextMatcher.matches(query, account.getUserId(), account.getMailAddress())) {
                continue;
            }
            result.add(ContactResponse.fromAccount(account));
        }
        for (MailContact contact : contactRepository.findActiveByUserSeq(user.getUserSeq())) {
            if (directoryEmails.contains(contact.getEmail().toLowerCase(Locale.ROOT))) {
                continue;
            }
            if (!KoreanTextMatcher.matches(query, contact.getDisplayName(), contact.getEmail())) {
                continue;
            }
            result.add(ContactResponse.from(contact));
        }

        return result;
    }

    private ContactGroupResponse toGroupResponse(
            MailContactGroup group, Long viewerUserSeq, Set<String> directoryEmails) {
        boolean owned = Objects.equals(group.getOwnerUserSeq(), viewerUserSeq);
        MailContactGroupShare share = owned
                ? null
                : shareRepository.findActive(group.getGroupSeq(), viewerUserSeq).orElse(null);
        ContactSharePermission permission = owned
                ? ContactSharePermission.WRITE
                : share != null ? share.getPermission() : ContactSharePermission.READ;
        List<ContactResponse> members = new ArrayList<>();
        List<Long> memberUserSeqs = memberRepository.findUserSeqsByGroupSeq(group.getGroupSeq());
        for (SysUser account : sysUserQueryRepository.findActiveByUserSeqs(memberUserSeqs)) {
            members.add(ContactResponse.fromAccount(account));
        }
        List<Long> contactIds = memberRepository.findContactSeqsByGroupSeq(group.getGroupSeq());
        if (!contactIds.isEmpty()) {
            for (MailContact contact : contactRepository.findActiveBySeqs(contactIds)) {
                if (directoryEmails.contains(contact.getEmail().toLowerCase(Locale.ROOT))) {
                    continue;
                }
                members.add(ContactResponse.from(contact));
            }
        }

        String ownerUserId = userIdOf(group.getOwnerUserSeq());
        String sharedByUserId = null;
        if (!owned) {
            String actorId = userIdOf(share == null ? null : share.getCreatedBy());
            sharedByUserId = StringUtils.hasText(actorId) ? actorId : ownerUserId;
        }

        return ContactGroupResponse.of(group, owned, permission, ownerUserId, sharedByUserId, members);
    }

    private List<String> memberEmails(Long groupSeq) {
        Set<String> emails = new LinkedHashSet<>();
        List<Long> memberUserSeqs = memberRepository.findUserSeqsByGroupSeq(groupSeq);
        for (SysUser account : sysUserQueryRepository.findActiveByUserSeqs(memberUserSeqs)) {
            if (StringUtils.hasText(account.getMailAddress())) {
                emails.add(account.getMailAddress());
            }
        }
        List<Long> ids = memberRepository.findContactSeqsByGroupSeq(groupSeq);
        if (!ids.isEmpty()) {
            for (MailContact contact : contactRepository.findActiveBySeqs(ids)) {
                emails.add(contact.getEmail());
            }
        }

        return new ArrayList<>(emails);
    }

    private void requireAccess(MailContactGroup group, Long userSeq) {
        if (Objects.equals(group.getOwnerUserSeq(), userSeq)) {
            return;
        }
        if (shareRepository.findActive(group.getGroupSeq(), userSeq).isEmpty()) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
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

    private String userIdOf(Long userSeq) {
        if (userSeq == null) {
            return "";
        }
        return sysUserQueryRepository.findByUserSeq(userSeq).map(SysUser::getUserId).orElse("");
    }

    private SysUser requireUser(String userId) {
        return sysUserQueryRepository
                .findByUserId(userId)
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND, "User not found: " + userId));
    }

    private Set<String> accountEmails() {
        return accountEmails(sysUserQueryRepository.findAllActive());
    }

    private static Set<String> accountEmails(List<SysUser> accounts) {
        return accounts.stream()
                .map(SysUser::getMailAddress)
                .filter(StringUtils::hasText)
                .map(email -> email.toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    /**
     * WRITE 공유자도 자기 연락처를 넣을 수 있다. 그룹에는 소유자 주소록 행(또는 가입 계정)으로 맞춘다.
     */
    private List<MailContact> resolveMembersToOwner(
            List<Long> contactIds, Long ownerSeq, Long actorSeq, Set<Long> accountSeqs) {
        if (contactIds.isEmpty()) {
            return List.of();
        }
        List<MailContact> sources = contactRepository.findActiveBySeqs(contactIds);
        if (sources.size() != contactIds.size()) {
            throw new ApiException(ErrorCode.CONTACT_NOT_FOUND);
        }
        LinkedHashMap<String, MailContact> ownerByEmail = new LinkedHashMap<>();
        for (MailContact source : sources) {
            if (!Objects.equals(source.getUserSeq(), ownerSeq)
                    && !Objects.equals(source.getUserSeq(), actorSeq)) {
                throw new ApiException(ErrorCode.FORBIDDEN, "Group members must be owner or editor contacts");
            }
            SysUser account = sysUserQueryRepository.findActiveByMailIgnoreCase(source.getEmail()).orElse(null);
            if (account != null) {
                accountSeqs.add(account.getUserSeq());
                continue;
            }
            MailContact owned = contactRepository
                    .findActiveByUserAndEmail(ownerSeq, source.getEmail())
                    .orElseGet(() -> contactRepository.save(
                            MailContact.create(ownerSeq, source.getDisplayName(), source.getEmail())));
            ownerByEmail.putIfAbsent(owned.getEmail().toLowerCase(Locale.ROOT), owned);
        }

        return new ArrayList<>(ownerByEmail.values());
    }

    private static List<Long> distinct(List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }

        return ids.stream().filter(Objects::nonNull).distinct().toList();
    }

    private static String blankToNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}
