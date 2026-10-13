package spring_security.common.exception;

public record ErrorResponse(String code, String message) {

    /** ApiException의 코드 이름과 메시지를 응답 본문으로 변환. */
    public static ErrorResponse from(ApiException ex) {
        // code는 enum 이름(USER_NOT_FOUND). message는 예외에 넣은 문자열.
        return new ErrorResponse(ex.getErrorCode().name(), ex.getMessage());
    }
}
