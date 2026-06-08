package spring_security.api.auth.social;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
public class SocialLoginPrepareController {

    @GetMapping("/auth/social/prepare/{provider}")
    public void prepare(
            @PathVariable String provider,
            @RequestParam String state,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("redirect_uri") String redirectUri,
            HttpServletRequest request,
            HttpSession session,
            HttpServletResponse response) throws IOException {

        session.setAttribute(SocialLoginAttributes.STATE, state);
        session.setAttribute(SocialLoginAttributes.CODE_CHALLENGE, codeChallenge);
        session.setAttribute(SocialLoginAttributes.REDIRECT_URI, redirectUri);

        String contextPath = request.getContextPath();
        response.sendRedirect(contextPath + "/oauth2/authorization/" + provider);
    }
}
