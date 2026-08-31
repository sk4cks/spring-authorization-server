package spring_security.contact.repository;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.JPAExpressions;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;
import spring_security.common.constants.DelYn;
import spring_security.contact.domain.MailContact;
import spring_security.contact.domain.MailContactGroup;
import spring_security.contact.domain.MailContactGroupShare;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static spring_security.contact.domain.QMailContact.mailContact;
import static spring_security.contact.domain.QMailContactGroup.mailContactGroup;
import static spring_security.contact.domain.QMailContactGroupMember.mailContactGroupMember;
import static spring_security.contact.domain.QMailContactGroupShare.mailContactGroupShare;

/**
 * 주소록 조회 (Querydsl).
 * 연락처·그룹·공유는 {@code delYn=N}만 본다. 멤버 테이블은 삭제 컬럼이 없어서 그룹 seq로만 고른다.
 */
@Repository
@RequiredArgsConstructor
public class ContactQueryRepository {

    private final JPAQueryFactory queryFactory;

    private static BooleanExpression contactAlive() {
        return mailContact.delYn.eq(DelYn.N);
    }

    private static BooleanExpression groupAlive() {
        return mailContactGroup.delYn.eq(DelYn.N);
    }

    private static BooleanExpression shareAlive() {
        return mailContactGroupShare.delYn.eq(DelYn.N);
    }

    /** 그 사용자가 직접 만든 활성 연락처. 표시명(없으면 이메일) 순. */
    public List<MailContact> findActiveByUserSeq(Long userSeq) {
        return queryFactory
                .selectFrom(mailContact)
                .where(mailContact.userSeq.eq(userSeq), contactAlive())
                .orderBy(mailContact.displayName.coalesce(mailContact.email).lower().asc())
                .fetch();
    }

    /** 내 활성 연락처 한 건. 삭제·권한 확인용. */
    public Optional<MailContact> findActiveBySeqAndUser(Long contactSeq, Long userSeq) {
        MailContact result = queryFactory
                .selectFrom(mailContact)
                .where(
                        mailContact.contactSeq.eq(contactSeq),
                        mailContact.userSeq.eq(userSeq),
                        contactAlive())
                .fetchOne();

        return Optional.ofNullable(result);
    }

    /** 내 주소록에 그 이메일이 이미 있는지. 대소문자 무시. */
    public boolean existsActiveEmail(Long userSeq, String email) {
        if (!StringUtils.hasText(email)) {
            return false;
        }

        Integer found = queryFactory
                .selectOne()
                .from(mailContact)
                .where(
                        mailContact.userSeq.eq(userSeq),
                        contactAlive(),
                        mailContact.email.lower().eq(email.trim().toLowerCase(Locale.ROOT)))
                .fetchFirst();

        return found != null;
    }

    /** 그 사용자의 주소록에서 이메일로 한 건. 그룹 멤버를 소유자 행으로 맞출 때 쓴다. */
    public Optional<MailContact> findActiveByUserAndEmail(Long userSeq, String email) {
        if (!StringUtils.hasText(email)) {
            return Optional.empty();
        }

        MailContact result = queryFactory
                .selectFrom(mailContact)
                .where(
                        mailContact.userSeq.eq(userSeq),
                        contactAlive(),
                        mailContact.email.lower().eq(email.trim().toLowerCase(Locale.ROOT)))
                .fetchOne();

        return Optional.ofNullable(result);
    }

    /** contactSeq 목록으로 활성 연락처. 그룹 멤버 펼칠 때. */
    public List<MailContact> findActiveBySeqs(Collection<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }

        return queryFactory
                .selectFrom(mailContact)
                .where(mailContact.contactSeq.in(ids), contactAlive())
                .fetch();
    }

    /** 활성 그룹 한 건. 없으면 empty. */
    public Optional<MailContactGroup> findActiveBySeq(Long groupSeq) {
        MailContactGroup result = queryFactory
                .selectFrom(mailContactGroup)
                .where(mailContactGroup.groupSeq.eq(groupSeq), groupAlive())
                .fetchOne();

        return Optional.ofNullable(result);
    }

    /**
     * 이 사용자가 볼 수 있는 그룹.
     * 소유자이거나, MAIL_CONTACT_GROUP_SHARE에 활성 공유가 있는 그룹. 이름 순.
     */
    public List<MailContactGroup> findAccessibleByUser(Long userSeq) {
        return queryFactory
                .selectFrom(mailContactGroup)
                .where(
                        groupAlive(),
                        mailContactGroup.ownerUserSeq.eq(userSeq)
                                .or(mailContactGroup.groupSeq.in(
                                        JPAExpressions.select(mailContactGroupShare.groupSeq)
                                                .from(mailContactGroupShare)
                                                .where(
                                                        mailContactGroupShare.sharedWithUserSeq.eq(userSeq),
                                                        shareAlive()))))
                .orderBy(mailContactGroup.name.lower().asc())
                .fetch();
    }

    /** 그룹 멤버 중 MAIL_CONTACT 쪽 seq. 계정 멤버는 제외. */
    public List<Long> findContactSeqsByGroupSeq(Long groupSeq) {
        return queryFactory
                .select(mailContactGroupMember.contactSeq)
                .from(mailContactGroupMember)
                .where(
                        mailContactGroupMember.groupSeq.eq(groupSeq),
                        mailContactGroupMember.contactSeq.isNotNull())
                .fetch();
    }

    /** 여러 그룹의 MAIL_CONTACT 멤버 seq. 공유 그룹 자동완성에 쓴다. */
    public List<Long> findContactSeqsByGroupSeqs(Collection<Long> groupSeqs) {
        if (groupSeqs == null || groupSeqs.isEmpty()) {
            return List.of();
        }

        return queryFactory
                .select(mailContactGroupMember.contactSeq)
                .from(mailContactGroupMember)
                .where(
                        mailContactGroupMember.groupSeq.in(groupSeqs),
                        mailContactGroupMember.contactSeq.isNotNull())
                .fetch();
    }

    /** 그룹 멤버 중 가입 계정 USER_SEQ. 주소록 행 멤버는 제외. */
    public List<Long> findUserSeqsByGroupSeq(Long groupSeq) {
        return queryFactory
                .select(mailContactGroupMember.memberUserSeq)
                .from(mailContactGroupMember)
                .where(
                        mailContactGroupMember.groupSeq.eq(groupSeq),
                        mailContactGroupMember.memberUserSeq.isNotNull())
                .fetch();
    }

    /** 그 그룹의 활성 공유 목록. shareSeq 순. */
    public List<MailContactGroupShare> findActiveByGroupSeq(Long groupSeq) {
        return queryFactory
                .selectFrom(mailContactGroupShare)
                .where(mailContactGroupShare.groupSeq.eq(groupSeq), shareAlive())
                .orderBy(mailContactGroupShare.shareSeq.asc())
                .fetch();
    }

    /** 특정 사용자에게 이 그룹이 어떻게 공유됐는지. 권한 체크용. */
    public Optional<MailContactGroupShare> findActive(Long groupSeq, Long userSeq) {
        MailContactGroupShare result = queryFactory
                .selectFrom(mailContactGroupShare)
                .where(
                        mailContactGroupShare.groupSeq.eq(groupSeq),
                        mailContactGroupShare.sharedWithUserSeq.eq(userSeq),
                        shareAlive())
                .fetchOne();

        return Optional.ofNullable(result);
    }

    /** 공유 한 건. 그룹에 속한 활성 행인지 확인한 뒤 해제할 때 쓴다. */
    public Optional<MailContactGroupShare> findActiveBySeqAndGroup(Long shareSeq, Long groupSeq) {
        MailContactGroupShare result = queryFactory
                .selectFrom(mailContactGroupShare)
                .where(
                        mailContactGroupShare.shareSeq.eq(shareSeq),
                        mailContactGroupShare.groupSeq.eq(groupSeq),
                        shareAlive())
                .fetchOne();

        return Optional.ofNullable(result);
    }
}
