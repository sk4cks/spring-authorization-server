package spring_security.auth.oauth;

public final class OAuthLoginAttributes {

    public static final String STATE = "social.pkce.state";
    public static final String CODE_CHALLENGE = "social.pkce.code_challenge";
    public static final String REDIRECT_URI = "social.pkce.redirect_uri";

    /** OAuth2Authorization attribute — JWT sns_* 클레임 소스 */
    public static final String SNS_PROVIDER = "social.sns.provider";
    public static final String SNS_EXTERNAL_ID = "social.sns.external_id";
    public static final String SNS_EXTERNAL_EMAIL = "social.sns.external_email";

    private OAuthLoginAttributes() {}
}
