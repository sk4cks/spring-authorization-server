package spring_security.common.exception;

public record ErrorResponse(String code, String message) {

    public static ErrorResponse from(ApiException ex) {
        // code는 enum 이름(USER_NOT_FOUND). message는 예외에 넣은 문자열.
        return new ErrorResponse(ex.getErrorCode().name(), ex.getMessage());
    }
}
