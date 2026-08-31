package spring_security.contact.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
 * 그룹 공유 한 줄 (MAIL_CONTACT_GROUP_SHARE).
 * 한 그룹을 다른 SYS_USER에게 READ/WRITE로 열어 준다. 끊을 때는 soft delete.
 */
@Entity
@Table(name = "MAIL_CONTACT_GROUP_SHARE", schema = "note")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MailContactGroupShare {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "mail_contact_group_share_seq")
    @SequenceGenerator(
            name = "mail_contact_group_share_seq",
            sequenceName = "CONTACT_GROUP_SHARE_SEQ",
            schema = "note",
            allocationSize = 1)
    @Column(name = "SHARE_SEQ")
    private Long shareSeq;

    @Column(name = "GROUP_SEQ", nullable = false)
    private Long groupSeq;

    /** 공유받은 사람. */
    @Column(name = "SHARED_WITH_USER_SEQ", nullable = false)
    private Long sharedWithUserSeq;

    @Enumerated(EnumType.STRING)
    @Column(name = "PERMISSION", nullable = false, length = 10)
    private ContactSharePermission permission;

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

    /** 새 공유 행. createdBy는 공유를 건 사람. */
    public static MailContactGroupShare create(
            Long groupSeq, Long sharedWithUserSeq, ContactSharePermission permission, Long actorUserSeq) {
        MailContactGroupShare share = new MailContactGroupShare();
        share.groupSeq = groupSeq;
        share.sharedWithUserSeq = sharedWithUserSeq;
        share.permission = permission;
        share.createdBy = actorUserSeq;
        share.updatedBy = actorUserSeq;

        return share;
    }

    /** READ ↔ WRITE. 이미 공유 중인 대상에 다시 공유하면 여기로 온다. */
    public void updatePermission(ContactSharePermission permission, Long actorUserSeq) {
        this.permission = permission;
        this.updatedBy = actorUserSeq;
    }

    /** 공유 해제. 그룹 자체는 그대로다. */
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
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
