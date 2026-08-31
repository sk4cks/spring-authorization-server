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
import spring_security.contact.dto.ContactDto;
import spring_security.contact.dto.ContactGroupDto;
import spring_security.contact.dto.ContactShareDto;
import spring_security.contact.dto.RecipientSuggestItem;
import spring_security.contact.repository.ContactQueryRepository;
import spring_security.contact.repository.ContactRepository;
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

/**
 * 주소록 유스케이스.
 * 목록은 SYS_USER(가입 계정 디렉터리)와 MAIL_CONTACT(내가 수동 추가한 행)를 합치고,
 * 그룹은 소유/공유에 따라 멤버·권한을 붙여 내려준다.
 */
@Service
@RequiredArgsConstructor
public class ContactService {

    private final SysUserQueryRepository sysUserQueryRepository;
    private final ContactRepository contactRepository;
    private final ContactQueryRepository contactQueryRepository;

    /**
     * 주소록 목록. {@code q}는 이름/이메일 필터(한글 자모 매칭).
     */
    @Transactional(readOnly = true)
    public List<ContactDto.Response> listContacts(String userId, String q) {
        return collectContacts(requireUser(userId), q == null ? "" : q.trim());
    }

    /**
     * 내 주소록에 이메일 한 건을 넣는다.
     * SYS_USER 메일 또는 이미 가진 MAIL_CONTACT와 겹치면 CONTACT_ALREADY_EXISTS.
     */
    @Transactional
    public ContactDto.Response createContact(String userId, ContactDto.Request request) {
        SysUser user = requireUser(userId);
        String email = request.email().trim();

        if (sysUserQueryRepository.existsActiveMailIgnoreCase(email)
                || contactQueryRepository.existsActiveEmail(user.getUserSeq(), email)) {
            throw new ApiException(ErrorCode.CONTACT_ALREADY_EXISTS);
        }

        MailContact saved = contactRepository.save(
                MailContact.create(user.getUserSeq(), blankToNull(request.displayName()), email));

        return ContactDto.Response.from(saved);
    }

    /**
     * 내 MAIL_CONTACT를 soft delete.
     * 그 이메일이 가입 계정이면 디렉터리 항목이라 지우지 않는다.
     */
    @Transactional
    public void deleteContact(String userId, Long contactId) {
        SysUser user = requireUser(userId);
        MailContact contact = contactQueryRepository
                .findActiveBySeqAndUser(contactId, user.getUserSeq())
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_NOT_FOUND));

        // 디렉터리(SYS_USER)와 같은 이메일은 주소록 행만 지울 수 없다.
        if (sysUserQueryRepository.existsActiveMailIgnoreCase(contact.getEmail())) {
            throw new ApiException(ErrorCode.FORBIDDEN, "가입된 계정 연락처는 삭제할 수 없습니다.");
        }

        contact.softDelete(user.getUserSeq());
    }

    /**
     * 접근 가능한 그룹 목록(소유 + 공유받음). 멤버/권한은 {@link #toGroupResponse}에서 채운다.
     */
    @Transactional(readOnly = true)
    public List<ContactGroupDto.Response> listGroups(String userId) {
        SysUser user = requireUser(userId);
        Set<String> directoryEmails = accountEmails();

        return contactQueryRepository.findAccessibleByUser(user.getUserSeq()).stream()
                .map(group -> toGroupResponse(group, user.getUserSeq(), directoryEmails))
                .toList();
    }

    /** 호출자 소유 빈 그룹을 만든다. */
    @Transactional
    public ContactGroupDto.Response createGroup(String userId, ContactGroupDto.Request request) {
        SysUser user = requireUser(userId);
        MailContactGroup saved =
                contactRepository.save(MailContactGroup.create(user.getUserSeq(), request.name()));

        return ContactGroupDto.Response.of(
                saved, true, ContactSharePermission.WRITE, user.getUserId(), null, List.of());
    }

    /** 그룹 이름 변경. 소유자만. */
    @Transactional
    public ContactGroupDto.Response renameGroup(String userId, Long groupId, ContactGroupDto.Request request) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);

        if (!Objects.equals(group.getOwnerUserSeq(), user.getUserSeq())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }

        group.rename(request.name(), user.getUserSeq());

        return toGroupResponse(group, user.getUserSeq(), accountEmails());
    }

    /**
     * 그룹 soft delete. 소유자만.
     * 공유 목록도 같이 비활성화해서, 공유받은 사람 목록에서 사라지게 한다.
     */
    @Transactional
    public void deleteGroup(String userId, Long groupId) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);

        if (!Objects.equals(group.getOwnerUserSeq(), user.getUserSeq())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }

        group.softDelete(user.getUserSeq());

        // 그룹을 지우면 남은 공유 행도 같이 비활성화한다.
        for (MailContactGroupShare share : contactQueryRepository.findActiveByGroupSeq(groupId)) {
            share.softDelete(user.getUserSeq());
        }
    }

    /**
     * 그룹 멤버를 body의 contactIds + accountUserSeqs로 통째로 교체한다.
     * 기존 MAIL_CONTACT_GROUP_MEMBER는 지우고 다시 INSERT.
     * WRITE 공유자가 넣은 자기 연락처는 소유자 주소록 행으로 복사한다.
     */
    @Transactional
    public ContactGroupDto.Response replaceMembers(
            String userId, Long groupId, ContactGroupDto.MembersRequest request) {
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

        // 멤버는 patch가 아니라 전체 교체.
        contactRepository.deleteByGroupSeq(groupId);

        for (MailContact contact : ownerContacts) {
            contactRepository.save(MailContactGroupMember.ofContact(groupId, contact.getContactSeq()));
        }

        for (SysUser account : accounts) {
            contactRepository.save(MailContactGroupMember.ofAccount(groupId, account.getUserSeq()));
        }

        return toGroupResponse(group, user.getUserSeq(), accountEmails());
    }

    /** 그룹 공유 행 목록. 대상 userId를 SYS_USER에서 붙여서 내려준다. */
    @Transactional(readOnly = true)
    public List<ContactShareDto.Response> listShares(String userId, Long groupId) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        requireAccess(group, user.getUserSeq());

        return contactQueryRepository.findActiveByGroupSeq(groupId).stream()
                .map(share -> ContactShareDto.Response.of(
                        share,
                        sysUserQueryRepository
                                .findByUserSeq(share.getSharedWithUserSeq())
                                .map(SysUser::getUserId)
                                .orElse("")))
                .toList();
    }

    /**
     * 대상 사용자에게 그룹을 공유한다.
     * 이미 활성 공유가 있으면 permission만 바꾸고, 없으면 INSERT.
     */
    @Transactional
    public ContactShareDto.Response shareGroup(
            String userId, Long groupId, ContactShareDto.Request request) {
        SysUser actor = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        requireWrite(group, actor.getUserSeq());

        SysUser target = requireUser(request.sharedWithUserId());

        if (Objects.equals(target.getUserSeq(), actor.getUserSeq())
                || Objects.equals(target.getUserSeq(), group.getOwnerUserSeq())) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "Cannot share group with yourself");
        }

        MailContactGroupShare existing =
                contactQueryRepository.findActive(groupId, target.getUserSeq()).orElse(null);

        if (existing != null) {
            existing.updatePermission(request.permission(), actor.getUserSeq());

            return ContactShareDto.Response.of(existing, target.getUserId());
        }

        MailContactGroupShare saved = contactRepository.save(MailContactGroupShare.create(
                groupId, target.getUserSeq(), request.permission(), actor.getUserSeq()));

        return ContactShareDto.Response.of(saved, target.getUserId());
    }

    /**
     * 공유 한 건을 끊는다.
     * 공유받은 사람은 자기 행만, 소유자/WRITE는 아무 공유나 끊을 수 있다.
     */
    @Transactional
    public void revokeShare(String userId, Long groupId, Long shareId) {
        SysUser actor = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);
        MailContactGroupShare share = contactQueryRepository
                .findActiveBySeqAndGroup(shareId, groupId)
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_SHARE_NOT_FOUND));

        // 공유받은 사람은 자기 공유만 끊을 수 있고, 그 외는 WRITE가 필요하다.
        boolean ownShare = Objects.equals(share.getSharedWithUserSeq(), actor.getUserSeq());

        if (!ownShare) {
            requireWrite(group, actor.getUserSeq());
        }

        share.softDelete(actor.getUserSeq());
    }

    /**
     * 수신자 자동완성(최대 30).
     * 1) 이름 매칭되는 접근 가능 그룹(멤버 이메일 배열)
     * 2) 내 주소록 + 디렉터리 계정
     * 3) 공유받은 그룹의 멤버 연락처(내 MAIL_CONTACT가 아닌 행)
     */
    @Transactional(readOnly = true)
    public List<RecipientSuggestItem> suggest(String userId, String q) {
        SysUser user = requireUser(userId);
        String query = q == null ? "" : q.trim();
        List<RecipientSuggestItem> result = new ArrayList<>();
        List<MailContactGroup> accessible = contactQueryRepository.findAccessibleByUser(user.getUserSeq());

        for (MailContactGroup group : accessible) {
            if (!KoreanTextMatcher.matches(query, group.getName())) {
                continue;
            }

            List<String> emails = memberEmails(group.getGroupSeq());

            if (!emails.isEmpty() || StringUtils.hasText(query)) {
                result.add(RecipientSuggestItem.group(group.getGroupSeq(), group.getName(), emails));
            }
        }

        Map<String, ContactDto.Response> byEmail = new LinkedHashMap<>();

        for (ContactDto.Response contact : collectContacts(user, query)) {
            byEmail.put(contact.email().toLowerCase(Locale.ROOT), contact);
        }

        // 공유받은 그룹의 멤버는 내 MAIL_CONTACT가 아니므로 따로 붙인다.
        List<Long> sharedGroupIds = accessible.stream()
                .filter(g -> !Objects.equals(g.getOwnerUserSeq(), user.getUserSeq()))
                .map(MailContactGroup::getGroupSeq)
                .toList();

        if (!sharedGroupIds.isEmpty()) {
            List<Long> contactIds = contactQueryRepository.findContactSeqsByGroupSeqs(sharedGroupIds);

            if (!contactIds.isEmpty()) {
                for (MailContact contact : contactQueryRepository.findActiveBySeqs(contactIds)) {
                    if (!KoreanTextMatcher.matches(query, contact.getDisplayName(), contact.getEmail())) {
                        continue;
                    }

                    byEmail.putIfAbsent(
                            contact.getEmail().toLowerCase(Locale.ROOT), ContactDto.Response.from(contact));
                }
            }
        }

        for (ContactDto.Response contact : byEmail.values()) {
            Long suggestId = contact.fromAccount() ? contact.accountUserSeq() : contact.id();
            result.add(RecipientSuggestItem.contact(suggestId, contact.displayName(), contact.email()));
        }

        return result.stream().limit(30).toList();
    }

    /**
     * 목록/검색용 연락처를 만든다.
     * SYS_USER를 앞에 두고, 같은 이메일의 MAIL_CONTACT는 중복이라 뺀다.
     */
    private List<ContactDto.Response> collectContacts(SysUser user, String query) {
        List<SysUser> accounts = sysUserQueryRepository.findAllActive();
        Set<String> directoryEmails = accountEmails(accounts);
        List<ContactDto.Response> result = new ArrayList<>();

        for (SysUser account : accounts) {
            if (!StringUtils.hasText(account.getMailAddress())) {
                continue;
            }

            if (!KoreanTextMatcher.matches(query, account.getUserId(), account.getMailAddress())) {
                continue;
            }

            result.add(ContactDto.Response.fromAccount(account));
        }

        for (MailContact contact : contactQueryRepository.findActiveByUserSeq(user.getUserSeq())) {
            if (directoryEmails.contains(contact.getEmail().toLowerCase(Locale.ROOT))) {
                continue;
            }

            if (!KoreanTextMatcher.matches(query, contact.getDisplayName(), contact.getEmail())) {
                continue;
            }

            result.add(ContactDto.Response.from(contact));
        }

        return result;
    }

    /**
     * 그룹 한 건을 API 응답으로 만든다.
     * 소유자면 WRITE, 공유면 그 permission.
     * 멤버는 계정(memberUserSeq) 먼저, 그다음 주소록 행. 디렉터리와 같은 이메일의 주소록 행은 숨긴다.
     */
    private ContactGroupDto.Response toGroupResponse(
            MailContactGroup group, Long viewerUserSeq, Set<String> directoryEmails) {
        boolean owned = Objects.equals(group.getOwnerUserSeq(), viewerUserSeq);
        MailContactGroupShare share = owned
                ? null
                : contactQueryRepository.findActive(group.getGroupSeq(), viewerUserSeq).orElse(null);
        ContactSharePermission permission = owned
                ? ContactSharePermission.WRITE
                : share != null ? share.getPermission() : ContactSharePermission.READ;

        List<ContactDto.Response> members = new ArrayList<>();
        List<Long> memberUserSeqs = contactQueryRepository.findUserSeqsByGroupSeq(group.getGroupSeq());

        for (SysUser account : sysUserQueryRepository.findActiveByUserSeqs(memberUserSeqs)) {
            members.add(ContactDto.Response.fromAccount(account));
        }

        List<Long> contactIds = contactQueryRepository.findContactSeqsByGroupSeq(group.getGroupSeq());

        if (!contactIds.isEmpty()) {
            for (MailContact contact : contactQueryRepository.findActiveBySeqs(contactIds)) {
                if (directoryEmails.contains(contact.getEmail().toLowerCase(Locale.ROOT))) {
                    continue;
                }

                members.add(ContactDto.Response.from(contact));
            }
        }

        String ownerUserId = userIdOf(group.getOwnerUserSeq());
        String sharedByUserId = null;

        if (!owned) {
            String actorId = userIdOf(share == null ? null : share.getCreatedBy());
            sharedByUserId = StringUtils.hasText(actorId) ? actorId : ownerUserId;
        }

        return ContactGroupDto.Response.of(group, owned, permission, ownerUserId, sharedByUserId, members);
    }

    /** 그룹 멤버들의 메일 주소. 자동완성 그룹 칩에 넣는다. */
    private List<String> memberEmails(Long groupSeq) {
        Set<String> emails = new LinkedHashSet<>();
        List<Long> memberUserSeqs = contactQueryRepository.findUserSeqsByGroupSeq(groupSeq);

        for (SysUser account : sysUserQueryRepository.findActiveByUserSeqs(memberUserSeqs)) {
            if (StringUtils.hasText(account.getMailAddress())) {
                emails.add(account.getMailAddress());
            }
        }

        List<Long> ids = contactQueryRepository.findContactSeqsByGroupSeq(groupSeq);

        if (!ids.isEmpty()) {
            for (MailContact contact : contactQueryRepository.findActiveBySeqs(ids)) {
                emails.add(contact.getEmail());
            }
        }

        return new ArrayList<>(emails);
    }

    /** 그룹을 볼 수 있는지. 소유자이거나 활성 공유 행이 있어야 한다. */
    private void requireAccess(MailContactGroup group, Long userSeq) {
        if (Objects.equals(group.getOwnerUserSeq(), userSeq)) {
            return;
        }

        if (contactQueryRepository.findActive(group.getGroupSeq(), userSeq).isEmpty()) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
    }

    /** 멤버 교체·공유 변경용. 소유자이거나 permission=WRITE 공유여야 한다. */
    private void requireWrite(MailContactGroup group, Long userSeq) {
        if (Objects.equals(group.getOwnerUserSeq(), userSeq)) {
            return;
        }

        ContactSharePermission permission = contactQueryRepository
                .findActive(group.getGroupSeq(), userSeq)
                .map(MailContactGroupShare::getPermission)
                .orElse(null);

        if (permission != ContactSharePermission.WRITE) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
    }

    /** 활성 그룹 한 건. 없으면 CONTACT_GROUP_NOT_FOUND. */
    private MailContactGroup requireGroup(Long groupId) {
        return contactQueryRepository
                .findActiveBySeq(groupId)
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_GROUP_NOT_FOUND));
    }

    /** USER_SEQ → userId. 못 찾으면 빈 문자열. */
    private String userIdOf(Long userSeq) {
        if (userSeq == null) {
            return "";
        }

        return sysUserQueryRepository.findByUserSeq(userSeq).map(SysUser::getUserId).orElse("");
    }

    /** userId로 활성 SYS_USER. 없으면 USER_NOT_FOUND. */
    private SysUser requireUser(String userId) {
        return sysUserQueryRepository
                .findByUserId(userId)
                .orElseThrow(() -> new ApiException(ErrorCode.USER_NOT_FOUND, "User not found: " + userId));
    }

    /** 가입 계정 메일 소문자 집합. 개인 연락처와 겹치는지 볼 때 쓴다. */
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
     * 그룹에 넣을 MAIL_CONTACT를 소유자 주소록 기준으로 맞춘다.
     * WRITE 공유자가 자기 연락처 id를 보내도, 가입 계정이면 accountSeqs에 넣고
     * 아니면 소유자 MAIL_CONTACT를 찾거나 새로 만든다. 그룹 멤버는 항상 소유자 쪽 행을 가리킨다.
     */
    private List<MailContact> resolveMembersToOwner(
            List<Long> contactIds, Long ownerSeq, Long actorSeq, Set<Long> accountSeqs) {
        if (contactIds.isEmpty()) {
            return List.of();
        }

        List<MailContact> sources = contactQueryRepository.findActiveBySeqs(contactIds);

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

            MailContact owned = contactQueryRepository
                    .findActiveByUserAndEmail(ownerSeq, source.getEmail())
                    .orElseGet(() -> contactRepository.save(
                            MailContact.create(ownerSeq, source.getDisplayName(), source.getEmail())));
            ownerByEmail.putIfAbsent(owned.getEmail().toLowerCase(Locale.ROOT), owned);
        }

        return new ArrayList<>(ownerByEmail.values());
    }

    /** null/중복 id 제거. 멤버 교체 body 정리. */
    private static List<Long> distinct(List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }

        return ids.stream().filter(Objects::nonNull).distinct().toList();
    }

    /** 빈 표시명은 DB에 null. */
    private static String blankToNull(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }
}
