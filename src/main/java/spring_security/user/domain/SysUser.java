package spring_security.user.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PostPersist;
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
@Table(name = "SYS_USER", schema = "note")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class SysUser {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sys_user_seq")
    @SequenceGenerator(
            name = "sys_user_seq",
            sequenceName = "USER_SEQ",
            schema = "note",
            allocationSize = 1)
    @Column(name = "USER_SEQ")
    private Long userSeq;

    @Column(name = "USER_ID", nullable = false, length = 64)
    private String userId;

    @Column(name = "MAIL_ADDRESS", nullable = false, length = 255)
    private String mailAddress;

    @Column(name = "PASSWORD_HASH", length = 255)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "AUTH_PROVIDER", nullable = false, length = 20)
    private AuthProvider authProvider;

    @Column(name = "EXTERNAL_ID", length = 255)
    private String externalId;

    @Column(name = "EXTERNAL_EMAIL", length = 255)
    private String externalEmail;

    @Enumerated(EnumType.STRING)
    @Column(name = "STATUS", nullable = false, length = 20)
    private UserStatus status;

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

    private SysUser(
            String userId,
            String mailAddress,
            String passwordHash,
            AuthProvider authProvider,
            String externalId,
            String externalEmail) {
        this.userId = userId;
        this.mailAddress = mailAddress;
        this.passwordHash = passwordHash;
        this.authProvider = authProvider;
        this.externalId = externalId;
        this.externalEmail = externalEmail;
        this.status = UserStatus.ACTIVE;
        this.delYn = DelYn.N;
    }

    public static SysUser createLocal(String userId, String mailAddress, String passwordHash) {
        return new SysUser(userId, mailAddress, passwordHash, AuthProvider.LOCAL, null, null);
    }

    public static SysUser createSocial(
            String userId,
            String mailAddress,
            AuthProvider authProvider,
            String externalId,
            String externalEmail) {
        return new SysUser(userId, mailAddress, null, authProvider, externalId, externalEmail);
    }

    public boolean isActive() {
        return status == UserStatus.ACTIVE && DelYn.N.equals(delYn);
    }

    /** 탈퇴(soft delete) — DEL_YN=Y, STATUS=INACTIVE */
    public void softDelete(Long actorUserSeq) {
        if (DelYn.isDeleted(delYn)) {
            return;
        }
        this.delYn = DelYn.Y;
        this.deletedAt = LocalDateTime.now();
        this.status = UserStatus.INACTIVE;
        this.updatedBy = actorUserSeq;
    }

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
        if (delYn == null) {
            delYn = DelYn.N;
        }
    }

    /** 본인 가입 등 — INSERT 후 USER_SEQ 로 등록/수정자 기록 */
    @PostPersist
    void assignAuditOnCreate() {
        if (createdBy == null) {
            createdBy = userSeq;
        }
        if (updatedBy == null) {
            updatedBy = userSeq;
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
