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

/**
 * 사용자가 직접 추가한 개인 연락처 (MAIL_CONTACT).
 * 가입 계정(SYS_USER)과 이메일이 같으면 목록 API에서는 이 행을 숨기고 계정을 보여 준다.
 */
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

    /** 이 연락처를 소유한 SYS_USER. */
    @Column(name = "USER_SEQ", nullable = false)
    private Long userSeq;

    /** 화면 표시명. 없으면 이메일만 쓴다. */
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

    /** N=활성, Y=삭제. 목록 쿼리는 N만 본다. */
    @Column(name = "DEL_YN", nullable = false, length = 1)
    private String delYn;

    @Column(name = "DELETED_AT")
    private LocalDateTime deletedAt;

    /** 내 주소록에 새 행. email은 trim. */
    public static MailContact create(Long userSeq, String displayName, String email) {
        MailContact contact = new MailContact();
        contact.userSeq = userSeq;
        contact.displayName = displayName;
        contact.email = email.trim();

        return contact;
    }

    /** DEL_YN=Y. 실제 DELETE는 하지 않는다. */
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
