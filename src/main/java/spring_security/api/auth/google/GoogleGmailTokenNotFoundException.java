package spring_security.api.auth.google;

public class GoogleGmailTokenNotFoundException extends RuntimeException {

    private final String principalName;

    public GoogleGmailTokenNotFoundException(String principalName) {
        super("Google Gmail token not found for principal: " + principalName);
        this.principalName = principalName;
    }

    public String getPrincipalName() {
        return principalName;
    }
}
