package spring_security.common.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleApiException(ApiException ex) {
        // HTTP 상태는 ErrorCode, body는 code+message. 스택은 응답에 안 넣는다.
        return ResponseEntity.status(ex.getErrorCode().getStatus())
                .body(ErrorResponse.from(ex));
    }
}
