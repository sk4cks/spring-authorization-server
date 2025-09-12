package spring_security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2AuthorizationController {

    @Autowired
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @GetMapping("/authorization")
    public OAuth2Authorization oAuth2Authorization(String token) {
        return this.oAuth2AuthorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
    }
}
