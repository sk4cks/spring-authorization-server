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
 * 연락처 그룹 (MAIL_CONTACT_GROUP).
 * 이름 변경·삭제는 소유자만. WRITE 공유자는 멤버·공유만 바꿀 수 있다.
 */
@Entity
@Table(name = "MAIL_CONTACT_GROUP", schema = "note")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MailContactGroup {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "mail_contact_group_seq")
    @SequenceGenerator(
            name = "mail_contact_group_seq",
            sequenceName = "CONTACT_GROUP_SEQ",
            schema = "note",
            allocationSize = 1)
    @Column(name = "GROUP_SEQ")
    private Long groupSeq;

    /** 그룹을 만든 SYS_USER. */
    @Column(name = "OWNER_USER_SEQ", nullable = false)
    private Long ownerUserSeq;

    @Column(name = "NAME", nullable = false, length = 120)
    private String name;

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

    /** 소유자 명의의 빈 그룹. */
    public static MailContactGroup create(Long ownerUserSeq, String name) {
        MailContactGroup group = new MailContactGroup();
        group.ownerUserSeq = ownerUserSeq;
        group.name = name.trim();

        return group;
    }

    /** 그룹 이름만 바꾼다. */
    public void rename(String name, Long actorUserSeq) {
        this.name = name.trim();
        this.updatedBy = actorUserSeq;
    }

    /** DEL_YN=Y. 멤버 행은 그대로 두고 그룹만 숨긴다. */
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
            this.createdBy = this.ownerUserSeq;
        }

        if (this.updatedBy == null) {
            this.updatedBy = this.ownerUserSeq;
        }
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
