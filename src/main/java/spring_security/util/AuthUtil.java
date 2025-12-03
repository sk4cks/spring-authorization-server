package spring_security.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

public class AuthUtil {

    public static void setCookie(String key, String value, HttpServletResponse response) {
        Cookie cookie = new Cookie(key, value);
        cookie.setHttpOnly(false); // 클라이언트 측 스크립트에서 쿠키에 접근할 수 없도록 설정
        cookie.setSecure(false); // 로컬 네트워크에서 HTTP를 사용하는 경우 false로 설정
        cookie.setPath("/");
        cookie.setMaxAge(300); // 5분
        response.addCookie(cookie);
    }
}
