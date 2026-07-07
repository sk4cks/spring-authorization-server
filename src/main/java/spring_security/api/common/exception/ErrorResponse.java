package spring_security.api.common.exception;

public record ErrorResponse(String code, String message) {

    public static ErrorResponse from(AppException ex) {
        return new ErrorResponse(ex.getErrorCode().name(), ex.getMessage());
    }
}
