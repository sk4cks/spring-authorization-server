package spring_security.common.exception;

public class ApiException extends RuntimeException {

    private final ErrorCode errorCode;

    /** 코드 기본 메시지로 던지는 예외. */
    public ApiException(ErrorCode errorCode) {
        // 메시지 없이 코드 기본 문구.
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
    }

    /** 구체 사유를 메시지에 붙이는 예외. */
    public ApiException(ErrorCode errorCode, String message) {
        // 컨트롤러/서비스에서 구체 사유를 붙일 때.
        super(message);
        this.errorCode = errorCode;
    }

    /** 원인 예외를 함께 감싸는 생성. */
    public ApiException(ErrorCode errorCode, Throwable cause) {
        // 로그인 실패처럼 원인을 감출 때. HTTP 메시지는 기본 문구.
        super(errorCode.getDefaultMessage(), cause);
        this.errorCode = errorCode;
    }

    /** 응답에 실을 에러 코드 조회. */
    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
