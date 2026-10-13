package spring_security.common.constants;

/**
 * DB {@code DEL_YN} 컬럼 공통 값 (CHAR(1)).
 * SYS_USER 외 테이블에서도 같은 값으로 사용.
 */
public final class DelYn {

    public static final String N = "N";
    public static final String Y = "Y";

    /** 인스턴스 없이 상수만 쓰는 유틸. */
    private DelYn() {}

    /** Y면 삭제. null은 삭제 아님. */
    public static boolean isDeleted(String delYn) {
        // null은 삭제 아님. 엔티티 PrePersist 전에만 가능.
        return Y.equals(delYn);
    }
}
