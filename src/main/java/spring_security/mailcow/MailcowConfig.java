package spring_security.mailcow;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;

@Configuration
public class MailcowConfig {

    /**
     * 로컬 Mailcow self-signed 전용 RestTemplate.
     * JVM 전역 SSL 기본값은 변경 없음 (Google OAuth 등 다른 HTTPS와 분리).
     */
    @Bean(name = "mailcowRestTemplate")
    RestTemplate mailcowRestTemplate(RestTemplateBuilder builder) throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");

        // Mailcow 컨테이너 self-signed만 통과. HttpsURLConnection마다 이 팩토리 적용.
        sslContext.init(null, trustAllManagers(), new SecureRandom());

        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory() {
            /** Mailcow self-signed만 통과하는 SSL 적용. */
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                if (connection instanceof HttpsURLConnection https) {
                    https.setSSLSocketFactory(sslContext.getSocketFactory());
                    https.setHostnameVerifier((hostname, session) -> true);
                }

                super.prepareConnection(connection, httpMethod);
            }
        };
        requestFactory.setConnectTimeout(Duration.ofSeconds(5));
        requestFactory.setReadTimeout(Duration.ofSeconds(15));

        return builder.requestFactory(() -> requestFactory).build();
    }

    /** Mailcow self-signed 통과용 TrustManager. */
    private static TrustManager[] trustAllManagers() {
        return new TrustManager[]{
                new X509TrustManager() {
                    /** self-signed 통과용. 클라이언트 인증서 검사 생략. */
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    /** self-signed 통과용. 서버 인증서 검사 생략. */
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    /** self-signed 통과용. 허용 issuer 없음. */
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
    }
}
