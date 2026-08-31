package spring_security.contact.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 그룹 멤버 한 줄 (MAIL_CONTACT_GROUP_MEMBER).
 * {@code contactSeq}(주소록 행)와 {@code memberUserSeq}(가입 계정) 중 하나만 채운다.
 * 삭제 컬럼이 없어서 멤버 교체 시 그룹 단위로 DELETE 후 다시 INSERT한다.
 */
@Entity
@Table(name = "MAIL_CONTACT_GROUP_MEMBER", schema = "note")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MailContactGroupMember {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "mail_contact_group_member_seq")
    @SequenceGenerator(
            name = "mail_contact_group_member_seq",
            sequenceName = "CONTACT_GROUP_MEMBER_SEQ",
            schema = "note",
            allocationSize = 1)
    @Column(name = "MEMBER_SEQ")
    private Long memberSeq;

    @Column(name = "GROUP_SEQ", nullable = false)
    private Long groupSeq;

    /** MAIL_CONTACT PK. 계정 멤버면 null. */
    @Column(name = "CONTACT_SEQ")
    private Long contactSeq;

    /** SYS_USER PK. 주소록 멤버면 null. */
    @Column(name = "MEMBER_USER_SEQ")
    private Long memberUserSeq;

    @Column(name = "CREATED_AT", nullable = false)
    private LocalDateTime createdAt;

    /** 소유자 주소록 행을 멤버로 넣는다. */
    public static MailContactGroupMember ofContact(Long groupSeq, Long contactSeq) {
        MailContactGroupMember member = new MailContactGroupMember();
        member.groupSeq = groupSeq;
        member.contactSeq = contactSeq;

        return member;
    }

    /** 가입 계정을 멤버로 넣는다. */
    public static MailContactGroupMember ofAccount(Long groupSeq, Long memberUserSeq) {
        MailContactGroupMember member = new MailContactGroupMember();
        member.groupSeq = groupSeq;
        member.memberUserSeq = memberUserSeq;

        return member;
    }

    @PrePersist
    void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}
