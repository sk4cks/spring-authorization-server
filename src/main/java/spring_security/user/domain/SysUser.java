package spring_security.user.domain;

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

    /** Mailcow 메일함 비밀번호 (AES 암호문). IMAP/SMTP용. */
    @Column(name = "MAILBOX_PASSWORD_ENC", length = 512)
    private String mailboxPasswordEnc;

    /** 감사 컬럼과 함께 사용자 행을 만드는 생성. */
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

    /** 로컬 계정 생성. SNS 필드는 비우고 비밀번호 해시 저장. */
    public static SysUser createLocal(String userId, String mailAddress, String passwordHash) {
        // SNS 필드는 비우고, passwordHash는 {bcrypt}...
        return new SysUser(userId, mailAddress, passwordHash, AuthProvider.LOCAL, null, null);
    }

    /** SNS 계정 생성. 앱 비밀번호는 없음. */
    public static SysUser createSocial(
            String userId,
            String mailAddress,
            AuthProvider authProvider,
            String externalId,
            String externalEmail) {
        // 앱 비밀번호는 없음. 메일함 비번은 가입 후 랜덤으로 저장.
        return new SysUser(userId, mailAddress, null, authProvider, externalId, externalEmail);
    }

    /** ACTIVE이고 미탈퇴인지 확인. */
    public boolean isActive() {
        return status == UserStatus.ACTIVE && DelYn.N.equals(delYn);
    }

    /** Mailcow에 넣은 평문을 암호화한 값을 저장 (가입/온보딩). */
    public void assignMailboxPasswordEnc(String mailboxPasswordEnc) {
        this.mailboxPasswordEnc = mailboxPasswordEnc;
    }

    /** 탈퇴(soft delete) — DEL_YN=Y, STATUS=INACTIVE */
    public void softDelete(Long actorUserSeq) {
        // 이미 탈퇴면 재호출해도 상태를 덮지 않음.
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

        // SEQUENCE 전략: persist 시 INSERT 전에 USER_SEQ 가 할당됨 → 한 번 INSERT 로 감사 컬럼까지 기록
        if (userSeq == null) {
            throw new IllegalStateException("USER_SEQ must be assigned before insert");
        }

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
