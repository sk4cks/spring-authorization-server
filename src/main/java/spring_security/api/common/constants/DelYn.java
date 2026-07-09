package spring_security.api.common.constants;

/**
 * DB {@code DEL_YN} 컬럼 공통 값 (CHAR(1)).
 * SYS_USER 외 테이블에서도 동일하게 사용한다.
 */
public final class DelYn {

    public static final String N = "N";
    public static final String Y = "Y";

    private DelYn() {}

    public static boolean isDeleted(String delYn) {
        return Y.equals(delYn);
    }
}
