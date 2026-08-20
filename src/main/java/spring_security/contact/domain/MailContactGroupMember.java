package spring_security.contact.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

@Entity
@Table(name = "MAIL_CONTACT_GROUP_MEMBER", schema = "note")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@IdClass(MailContactGroupMember.Pk.class)
public class MailContactGroupMember {

    @Id
    @Column(name = "GROUP_SEQ")
    private Long groupSeq;

    @Id
    @Column(name = "CONTACT_SEQ")
    private Long contactSeq;

    @Column(name = "CREATED_AT", nullable = false)
    private LocalDateTime createdAt;

    public static MailContactGroupMember of(Long groupSeq, Long contactSeq) {
        MailContactGroupMember member = new MailContactGroupMember();
        member.groupSeq = groupSeq;
        member.contactSeq = contactSeq;
        return member;
    }

    @PrePersist
    void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @EqualsAndHashCode
    public static class Pk implements Serializable {
        private Long groupSeq;
        private Long contactSeq;
    }
}
