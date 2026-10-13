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
 * 그룹은 소유/공유에 따라 멤버·권한을 붙여 응답.
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
        // userId로 활성 SYS_USER 조회. 검색어는 null이면 빈 문자열.
        return collectContacts(requireUser(userId), q == null ? "" : q.trim());
    }

    /**
     * 내 주소록에 이메일 한 건 추가.
     * SYS_USER 메일 또는 이미 가진 MAIL_CONTACT와 겹치면 CONTACT_ALREADY_EXISTS.
     */
    @Transactional
    public ContactDto.Response createContact(String userId, ContactDto.Request request) {
        // 이 주소록을 소유할 로그인 사용자.
        SysUser user = requireUser(userId);

        // 비교·저장은 공백 없는 이메일.
        String email = request.email().trim();

        // 가입 계정 메일이거나, 이미 내 MAIL_CONTACT에 있으면 추가 생략.
        if (sysUserQueryRepository.existsActiveMailIgnoreCase(email)
                || contactQueryRepository.existsActiveEmail(user.getUserSeq(), email)) {
            throw new ApiException(ErrorCode.CONTACT_ALREADY_EXISTS);
        }

        // 표시명이 빈 문자열이면 null로 넣고 INSERT.
        MailContact saved = contactRepository.save(
                MailContact.create(user.getUserSeq(), blankToNull(request.displayName()), email));

        // API는 엔티티가 아니라 ContactDto.Response 모양으로 응답.
        return ContactDto.Response.from(saved);
    }

    /**
     * 내 MAIL_CONTACT를 soft delete.
     * 그 이메일이 가입 계정이면 디렉터리 항목이라 삭제 생략.
     */
    @Transactional
    public void deleteContact(String userId, Long contactId) {
        SysUser user = requireUser(userId);

        // 내 것 + 활성 행만. 없으면 없는 연락처.
        MailContact contact = contactQueryRepository
                .findActiveBySeqAndUser(contactId, user.getUserSeq())
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_NOT_FOUND));

        // 디렉터리(SYS_USER)와 같은 이메일은 주소록 행만 삭제 불가.
        if (sysUserQueryRepository.existsActiveMailIgnoreCase(contact.getEmail())) {
            throw new ApiException(ErrorCode.FORBIDDEN, "가입된 계정 연락처는 삭제할 수 없습니다.");
        }

        // DEL_YN=Y. 목록 쿼리에서 제외.
        contact.softDelete(user.getUserSeq());
    }

    /**
     * 접근 가능한 그룹 목록(소유 + 공유받음). 멤버/권한은 {@link #toGroupResponse}에서 채움.
     */
    @Transactional(readOnly = true)
    public List<ContactGroupDto.Response> listGroups(String userId) {
        SysUser user = requireUser(userId);

        // 가입 계정 메일 집합. 그룹 멤버 중 같은 이메일의 MAIL_CONTACT는 숨김.
        Set<String> directoryEmails = accountEmails();

        // 소유 그룹 + 공유받은 그룹을 응답 DTO로 변환.
        return contactQueryRepository.findAccessibleByUser(user.getUserSeq()).stream()
                .map(group -> toGroupResponse(group, user.getUserSeq(), directoryEmails))
                .toList();
    }

    /** 호출자 소유 빈 그룹 생성. */
    @Transactional
    public ContactGroupDto.Response createGroup(String userId, ContactGroupDto.Request request) {
        SysUser user = requireUser(userId);

        // 소유자는 호출자, 멤버는 아직 없음.
        MailContactGroup saved =
                contactRepository.save(MailContactGroup.create(user.getUserSeq(), request.name()));

        // 방금 만들었으니 owned=true, 권한 WRITE, 공유한 사람 없음.
        return ContactGroupDto.Response.of(
                saved, true, ContactSharePermission.WRITE, user.getUserId(), null, List.of());
    }

    /** 그룹 이름 변경. 소유자만. */
    @Transactional
    public ContactGroupDto.Response renameGroup(String userId, Long groupId, ContactGroupDto.Request request) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);

        // WRITE 공유자도 이름은 변경 불가. 소유자 PK가 같아야 함.
        if (!Objects.equals(group.getOwnerUserSeq(), user.getUserSeq())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }

        group.rename(request.name(), user.getUserSeq());

        // 멤버·권한까지 다시 채워 반환.
        return toGroupResponse(group, user.getUserSeq(), accountEmails());
    }

    /**
     * 그룹 soft delete. 소유자만.
     * 공유 목록도 같이 비활성화해서, 공유받은 사람 목록에서 제외.
     */
    @Transactional
    public void deleteGroup(String userId, Long groupId) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);

        if (!Objects.equals(group.getOwnerUserSeq(), user.getUserSeq())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }

        group.softDelete(user.getUserSeq());

        // 그룹을 지우면 남은 공유 행도 같이 비활성화.
        for (MailContactGroupShare share : contactQueryRepository.findActiveByGroupSeq(groupId)) {
            share.softDelete(user.getUserSeq());
        }
    }

    /**
     * 그룹 멤버를 body의 contactIds + accountUserSeqs로 통째로 교체.
     * 기존 MAIL_CONTACT_GROUP_MEMBER는 지우고 다시 INSERT.
     * WRITE 공유자가 넣은 자기 연락처는 소유자 주소록 행으로 복사.
     */
    @Transactional
    public ContactGroupDto.Response replaceMembers(
            String userId, Long groupId, ContactGroupDto.MembersRequest request) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);

        // 소유자 또는 WRITE 공유만 멤버 변경.
        requireWrite(group, user.getUserSeq());

        Long ownerSeq = group.getOwnerUserSeq();

        // body가 null이거나 중복 id가 있어도 한 번씩만 사용.
        List<Long> contactIds = distinct(request == null ? null : request.contactIds());
        List<Long> accountUserSeqs = distinct(request == null ? null : request.accountUserSeqs());

        // 연락처 이메일이 가입 계정이면 여기로 합침.
        LinkedHashSet<Long> accountSeqs = new LinkedHashSet<>(accountUserSeqs);

        // WRITE 공유자의 연락처 id → 소유자 MAIL_CONTACT 행(또는 계정 seq).
        List<MailContact> ownerContacts = resolveMembersToOwner(contactIds, ownerSeq, user.getUserSeq(), accountSeqs);
        List<SysUser> accounts = sysUserQueryRepository.findActiveByUserSeqs(accountSeqs);

        // 요청한 계정 seq 중 없는 사용자가 있으면 멤버 추가 생략.
        if (accounts.size() != accountSeqs.size()) {
            throw new ApiException(ErrorCode.USER_NOT_FOUND, "Group members must be registered accounts");
        }

        // 멤버는 patch가 아니라 전체 교체.
        contactRepository.deleteByGroupSeq(groupId);

        // 주소록 행 멤버 INSERT.
        for (MailContact contact : ownerContacts) {
            contactRepository.save(MailContactGroupMember.ofContact(groupId, contact.getContactSeq()));
        }

        // 가입 계정 멤버 INSERT.
        for (SysUser account : accounts) {
            contactRepository.save(MailContactGroupMember.ofAccount(groupId, account.getUserSeq()));
        }

        return toGroupResponse(group, user.getUserSeq(), accountEmails());
    }

    /** 그룹 공유 행 목록. 대상 userId를 SYS_USER에서 붙여 응답. */
    @Transactional(readOnly = true)
    public List<ContactShareDto.Response> listShares(String userId, Long groupId) {
        SysUser user = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);

        // 소유자 또는 공유받은 사람만 목록 조회.
        requireAccess(group, user.getUserSeq());

        // sharedWithUserSeq → 로그인 id. 탈퇴 등이면 빈 문자열.
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
     * 대상 사용자에게 그룹 공유.
     * 이미 활성 공유가 있으면 permission만 바꾸고, 없으면 INSERT.
     */
    @Transactional
    public ContactShareDto.Response shareGroup(
            String userId, Long groupId, ContactShareDto.Request request) {
        SysUser actor = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);

        requireWrite(group, actor.getUserSeq());

        // 공유받을 사람. userId로 SYS_USER 조회.
        SysUser target = requireUser(request.sharedWithUserId());

        // 본인·그룹 소유자에게 공유하는 요청은 거절.
        if (Objects.equals(target.getUserSeq(), actor.getUserSeq())
                || Objects.equals(target.getUserSeq(), group.getOwnerUserSeq())) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "Cannot share group with yourself");
        }

        MailContactGroupShare existing =
                contactQueryRepository.findActive(groupId, target.getUserSeq()).orElse(null);

        if (existing != null) {
            // 이미 공유 중이면 행을 새로 만들지 않고 권한만 갱신.
            existing.updatePermission(request.permission(), actor.getUserSeq());

            return ContactShareDto.Response.of(existing, target.getUserId());
        }

        MailContactGroupShare saved = contactRepository.save(MailContactGroupShare.create(
                groupId, target.getUserSeq(), request.permission(), actor.getUserSeq()));

        return ContactShareDto.Response.of(saved, target.getUserId());
    }

    /**
     * 공유 한 건 해제.
     * 공유받은 사람은 자기 행만, 소유자/WRITE는 아무 공유나 해제.
     */
    @Transactional
    public void revokeShare(String userId, Long groupId, Long shareId) {
        SysUser actor = requireUser(userId);
        MailContactGroup group = requireGroup(groupId);

        // shareId가 이 그룹의 활성 행이어야 함.
        MailContactGroupShare share = contactQueryRepository
                .findActiveBySeqAndGroup(shareId, groupId)
                .orElseThrow(() -> new ApiException(ErrorCode.CONTACT_SHARE_NOT_FOUND));

        // 공유받은 사람은 자기 공유만 해제. 그 외는 WRITE 필요.
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

        // 소유 + 공유받은 그룹. 그룹 칩과 공유 멤버 연락처에 사용.
        List<MailContactGroup> accessible = contactQueryRepository.findAccessibleByUser(user.getUserSeq());

        // 1) 그룹 이름 매칭 → 멤버 메일을 담은 그룹 후보.
        for (MailContactGroup group : accessible) {
            if (!KoreanTextMatcher.matches(query, group.getName())) {
                continue;
            }

            List<String> emails = memberEmails(group.getGroupSeq());

            // 검색어가 있으면 빈 그룹도 보여주고, 없으면 멤버 있는 그룹만.
            if (!emails.isEmpty() || StringUtils.hasText(query)) {
                result.add(RecipientSuggestItem.group(group.getGroupSeq(), group.getName(), emails));
            }
        }

        // 이메일 소문자 키로 중복 방지. 계정 연락처가 개인 연락처보다 우선.
        Map<String, ContactDto.Response> byEmail = new LinkedHashMap<>();

        // 2) 디렉터리 + 내 MAIL_CONTACT.
        for (ContactDto.Response contact : collectContacts(user, query)) {
            byEmail.put(contact.email().toLowerCase(Locale.ROOT), contact);
        }

        // 공유받은 그룹의 멤버는 내 MAIL_CONTACT가 아니므로 따로 추가.
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

                    // 이미 내 목록에 있는 이메일은 덮어쓰기 생략.
                    byEmail.putIfAbsent(
                            contact.getEmail().toLowerCase(Locale.ROOT), ContactDto.Response.from(contact));
                }
            }
        }

        // 계정이면 accountUserSeq, 개인 연락처면 contactSeq를 자동완성 id로 사용.
        for (ContactDto.Response contact : byEmail.values()) {
            Long suggestId = contact.fromAccount() ? contact.accountUserSeq() : contact.id();
            result.add(RecipientSuggestItem.contact(suggestId, contact.displayName(), contact.email()));
        }

        return result.stream().limit(30).toList();
    }

    /**
     * 목록/검색용 연락처 조립.
     * SYS_USER를 앞에 두고, 같은 이메일의 MAIL_CONTACT는 중복이라 제외.
     */
    private List<ContactDto.Response> collectContacts(SysUser user, String query) {
        List<SysUser> accounts = sysUserQueryRepository.findAllActive();
        Set<String> directoryEmails = accountEmails(accounts);
        List<ContactDto.Response> result = new ArrayList<>();

        // 가입 계정 디렉터리. 메일 없는 계정은 주소록에서 제외.
        for (SysUser account : accounts) {
            if (!StringUtils.hasText(account.getMailAddress())) {
                continue;
            }

            if (!KoreanTextMatcher.matches(query, account.getUserId(), account.getMailAddress())) {
                continue;
            }

            result.add(ContactDto.Response.fromAccount(account));
        }

        // 내가 수동으로 넣은 행. 디렉터리와 이메일이 같으면 숨김.
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
     * 그룹 한 건을 API 응답으로 조립.
     * 소유자면 WRITE, 공유면 그 permission.
     * 멤버는 계정(memberUserSeq) 먼저, 그다음 주소록 행. 디렉터리와 같은 이메일의 주소록 행은 숨김.
     */
    private ContactGroupDto.Response toGroupResponse(
            MailContactGroup group, Long viewerUserSeq, Set<String> directoryEmails) {
        boolean owned = Objects.equals(group.getOwnerUserSeq(), viewerUserSeq);

        // 내 그룹이면 공유 행 조회 생략.
        MailContactGroupShare share = owned
                ? null
                : contactQueryRepository.findActive(group.getGroupSeq(), viewerUserSeq).orElse(null);

        // 공유 행이 비정상적으로 없으면 READ로 내려 화면이 깨지지 않게 유지.
        ContactSharePermission permission = owned
                ? ContactSharePermission.WRITE
                : share != null ? share.getPermission() : ContactSharePermission.READ;

        List<ContactDto.Response> members = new ArrayList<>();
        List<Long> memberUserSeqs = contactQueryRepository.findUserSeqsByGroupSeq(group.getGroupSeq());

        // 계정 멤버를 먼저 추가.
        for (SysUser account : sysUserQueryRepository.findActiveByUserSeqs(memberUserSeqs)) {
            members.add(ContactDto.Response.fromAccount(account));
        }

        List<Long> contactIds = contactQueryRepository.findContactSeqsByGroupSeq(group.getGroupSeq());

        if (!contactIds.isEmpty()) {
            for (MailContact contact : contactQueryRepository.findActiveBySeqs(contactIds)) {
                // 이미 계정으로 나온 이메일의 주소록 행은 중복이라 제외.
                if (directoryEmails.contains(contact.getEmail().toLowerCase(Locale.ROOT))) {
                    continue;
                }

                members.add(ContactDto.Response.from(contact));
            }
        }

        String ownerUserId = userIdOf(group.getOwnerUserSeq());
        String sharedByUserId = null;

        if (!owned) {
            // 공유를 건 사람. 없으면 소유자 id로 대체.
            String actorId = userIdOf(share == null ? null : share.getCreatedBy());
            sharedByUserId = StringUtils.hasText(actorId) ? actorId : ownerUserId;
        }

        return ContactGroupDto.Response.of(group, owned, permission, ownerUserId, sharedByUserId, members);
    }

    /** 그룹 멤버들의 메일 주소. 자동완성 그룹 칩에 포함. */
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

    /** 그룹 조회 가능 여부. 소유자이거나 활성 공유 행이 있어야 함. */
    private void requireAccess(MailContactGroup group, Long userSeq) {
        if (Objects.equals(group.getOwnerUserSeq(), userSeq)) {
            return;
        }

        // 공유 행이 없으면 이 그룹 조회 불가.
        if (contactQueryRepository.findActive(group.getGroupSeq(), userSeq).isEmpty()) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
    }

    /** 멤버 교체·공유 변경용. 소유자이거나 permission=WRITE 공유여야 함. */
    private void requireWrite(MailContactGroup group, Long userSeq) {
        if (Objects.equals(group.getOwnerUserSeq(), userSeq)) {
            return;
        }

        ContactSharePermission permission = contactQueryRepository
                .findActive(group.getGroupSeq(), userSeq)
                .map(MailContactGroupShare::getPermission)
                .orElse(null);

        // 공유가 없거나 READ면 수정 불가.
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

    /** 가입 계정 메일 소문자 집합. 개인 연락처와 겹치는지 볼 때 사용. */
    private Set<String> accountEmails() {
        return accountEmails(sysUserQueryRepository.findAllActive());
    }

    /** 메일 없는 계정은 빼고, 나머지는 소문자로 모으는 집합. */
    private static Set<String> accountEmails(List<SysUser> accounts) {
        // 메일 없는 계정은 제외하고, 비교는 소문자.
        return accounts.stream()
                .map(SysUser::getMailAddress)
                .filter(StringUtils::hasText)
                .map(email -> email.toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    /**
     * 그룹에 넣을 MAIL_CONTACT를 소유자 주소록 기준으로 맞춤.
     * WRITE 공유자가 자기 연락처 id를 보내도, 가입 계정이면 accountSeqs에 넣고
     * 아니면 소유자 MAIL_CONTACT 조회 또는 생성. 그룹 멤버는 항상 소유자 쪽 행.
     */
    private List<MailContact> resolveMembersToOwner(
            List<Long> contactIds, Long ownerSeq, Long actorSeq, Set<Long> accountSeqs) {
        if (contactIds.isEmpty()) {
            return List.of();
        }

        List<MailContact> sources = contactQueryRepository.findActiveBySeqs(contactIds);

        // 요청 id 개수와 조회 건수가 다르면 없는/삭제된 연락처가 섞임.
        if (sources.size() != contactIds.size()) {
            throw new ApiException(ErrorCode.CONTACT_NOT_FOUND);
        }

        // 같은 이메일은 한 행만. 입력 순서 유지.
        LinkedHashMap<String, MailContact> ownerByEmail = new LinkedHashMap<>();

        for (MailContact source : sources) {
            // 소유자 주소록도, 지금 수정하는 사람 주소록도 아니면 남의 연락처.
            if (!Objects.equals(source.getUserSeq(), ownerSeq)
                    && !Objects.equals(source.getUserSeq(), actorSeq)) {
                throw new ApiException(ErrorCode.FORBIDDEN, "Group members must be owner or editor contacts");
            }

            SysUser account = sysUserQueryRepository.findActiveByMailIgnoreCase(source.getEmail()).orElse(null);

            if (account != null) {
                // 가입 계정이면 MAIL_CONTACT 멤버가 아니라 계정 멤버로 추가.
                accountSeqs.add(account.getUserSeq());
                continue;
            }

            // 소유자 주소록에 같은 이메일이 있으면 그걸 쓰고, 없으면 소유자 명의로 복사 INSERT.
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
