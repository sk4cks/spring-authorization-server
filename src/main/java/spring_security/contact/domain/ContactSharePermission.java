package spring_security.contact.domain;

/**
 * 그룹 공유 권한.
 * READ: 그룹·멤버 조회만.
 * WRITE: 멤버 교체·다른 사람 공유까지. 그룹 이름 변경·삭제는 소유자만.
 */
public enum ContactSharePermission {
    READ,
    WRITE
}
