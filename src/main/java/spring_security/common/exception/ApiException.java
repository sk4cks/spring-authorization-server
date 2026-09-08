package spring_security.common.exception;

public class ApiException extends RuntimeException {

    private final ErrorCode errorCode;

    public ApiException(ErrorCode errorCode) {
        // 메시지 없이 코드 기본 문구.
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
    }

    public ApiException(ErrorCode errorCode, String message) {
        // 컨트롤러/서비스에서 구체 사유를 붙일 때.
        super(message);
        this.errorCode = errorCode;
    }

    public ApiException(ErrorCode errorCode, Throwable cause) {
        // 로그인 실패처럼 원인을 감출 때. HTTP 메시지는 기본 문구.
        super(errorCode.getDefaultMessage(), cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
