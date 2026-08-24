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

    @Column(name = "CONTACT_SEQ")
    private Long contactSeq;

    @Column(name = "MEMBER_USER_SEQ")
    private Long memberUserSeq;

    @Column(name = "CREATED_AT", nullable = false)
    private LocalDateTime createdAt;

    public static MailContactGroupMember ofContact(Long groupSeq, Long contactSeq) {
        MailContactGroupMember member = new MailContactGroupMember();
        member.groupSeq = groupSeq;
        member.contactSeq = contactSeq;
        return member;
    }

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
