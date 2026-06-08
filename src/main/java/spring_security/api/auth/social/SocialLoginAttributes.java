package spring_security.api.auth.social;

public final class SocialLoginAttributes {

    public static final String STATE = "social.pkce.state";
    public static final String CODE_CHALLENGE = "social.pkce.code_challenge";
    public static final String REDIRECT_URI = "social.pkce.redirect_uri";

    private SocialLoginAttributes() {}
}
