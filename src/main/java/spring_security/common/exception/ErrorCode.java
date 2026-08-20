package spring_security.common.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {

    USER_ALREADY_EXISTS(HttpStatus.CONFLICT, "User already exists"),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "User not found"),
    CONTACT_NOT_FOUND(HttpStatus.NOT_FOUND, "Contact not found"),
    CONTACT_ALREADY_EXISTS(HttpStatus.CONFLICT, "Contact email already exists"),
    CONTACT_GROUP_NOT_FOUND(HttpStatus.NOT_FOUND, "Contact group not found"),
    CONTACT_SHARE_NOT_FOUND(HttpStatus.NOT_FOUND, "Contact group share not found"),
    FORBIDDEN(HttpStatus.FORBIDDEN, "Forbidden"),
    GOOGLE_GMAIL_NOT_LINKED(HttpStatus.NOT_FOUND, "Google login with Gmail scope required"),
    MAILCOW_ERROR(HttpStatus.BAD_GATEWAY, "Mailcow mailbox provisioning failed"),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Unauthorized"),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Invalid userId or password"),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "Invalid request");

    private final HttpStatus status;
    private final String defaultMessage;

    ErrorCode(HttpStatus status, String defaultMessage) {
        this.status = status;
        this.defaultMessage = defaultMessage;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }
}
