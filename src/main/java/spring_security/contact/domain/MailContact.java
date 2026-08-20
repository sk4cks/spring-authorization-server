package spring_security.contact.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import spring_security.common.constants.DelYn;

import java.time.LocalDateTime;

@Entity
@Table(name = "MAIL_CONTACT", schema = "note")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MailContact {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "mail_contact_seq")
    @SequenceGenerator(
            name = "mail_contact_seq",
            sequenceName = "CONTACT_SEQ",
            schema = "note",
            allocationSize = 1)
    @Column(name = "CONTACT_SEQ")
    private Long contactSeq;

    @Column(name = "USER_SEQ", nullable = false)
    private Long userSeq;

    @Column(name = "DISPLAY_NAME", length = 120)
    private String displayName;

    @Column(name = "EMAIL", nullable = false, length = 255)
    private String email;

    @Column(name = "CREATED_AT", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "UPDATED_AT", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "CREATED_BY")
    private Long createdBy;

    @Column(name = "UPDATED_BY")
    private Long updatedBy;

    @Column(name = "DEL_YN", nullable = false, length = 1)
    private String delYn;

    @Column(name = "DELETED_AT")
    private LocalDateTime deletedAt;

    public static MailContact create(Long userSeq, String displayName, String email) {
        MailContact contact = new MailContact();
        contact.userSeq = userSeq;
        contact.displayName = displayName;
        contact.email = email.trim();
        return contact;
    }

    public void update(String displayName, String email, Long actorUserSeq) {
        this.displayName = displayName;
        this.email = email.trim();
        this.updatedBy = actorUserSeq;
    }

    public void softDelete(Long actorUserSeq) {
        if (DelYn.isDeleted(delYn)) {
            return;
        }
        this.delYn = DelYn.Y;
        this.deletedAt = LocalDateTime.now();
        this.updatedBy = actorUserSeq;
    }

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (this.delYn == null) {
            this.delYn = DelYn.N;
        }
        if (this.createdBy == null) {
            this.createdBy = this.userSeq;
        }
        if (this.updatedBy == null) {
            this.updatedBy = this.userSeq;
        }
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
