package spring_security.auth.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

/**
 * SPA PKCE를 세션에 넣고 SNS oauth2Login으로 이동.
 * 성공 후 {@link OAuthLoginSuccessHandler}가 이 세션을 읽어 /oauth/callback 으로 code 전달.
 */
@Controller
public class OAuthLoginPrepareController {

    /** SPA PKCE를 세션에 넣고 SNS oauth2Login으로 이동. */
    @GetMapping("/auth/social/prepare/{provider}")
    public void prepare(
            @PathVariable String provider,
            @RequestParam String state,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("redirect_uri") String redirectUri,
            HttpServletRequest request,
            HttpSession session,
            HttpServletResponse response) throws IOException {

        // OAuthLoginSuccessHandler가 SNS 로그인 직후 이 값으로 authorization_code 생성.
        session.setAttribute(OAuthLoginAttributes.STATE, state);
        session.setAttribute(OAuthLoginAttributes.CODE_CHALLENGE, codeChallenge);
        session.setAttribute(OAuthLoginAttributes.REDIRECT_URI, redirectUri);

        // /oauth2/authorization/google 등. context-path /authorization-api 를 붙임.
        String contextPath = request.getContextPath();
        response.sendRedirect(contextPath + "/oauth2/authorization/" + provider);
    }
}
