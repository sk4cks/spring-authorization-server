# Kakao OAuth 연동

Google SNS와 동일 흐름 — `provider`만 `kakao`.

## 1. Kakao Developers

1. [Kakao Developers](https://developers.kakao.com/) → 앱 생성
2. **앱 → 플랫폼 키 → REST API 키** (상세 들어가기)
   - **REST API 키** 값 = `KAKAO_CLIENT_ID` (JavaScript 키 아님)
   - 같은 화면 **클라이언트 시크릿** 섹션:
     1. **코드 생성** (또는 재발급)
     2. **활성화 상태 → 사용함(ON)**
     3. **저장**
   - 생성 직후에만 전체 값이 보임 — 복사해 두기 (나중엔 마스킹)
3. **제품 설정 → 카카오 로그인** — 활성화
4. **Redirect URI** — REST API 키 상세 또는 카카오 로그인 메뉴에서 등록:

| 환경 | URI |
|------|-----|
| 로컬 | `http://localhost:9000/authorization-api/login/oauth2/code/kakao` |
| EC2 | `https://auth.{EC2_IP}.nip.io/authorization-api/login/oauth2/code/kakao` |

5. **동의항목** — 닉네임(`profile_nickname`) **필수 동의** (이미 설정됨)

> **이메일(`account_email`) — 권한 없음이 정상인 경우가 많음**  
> 카카오는 이메일·전화번호 등에 **사업자/심사·개인정보 처리방침 URL** 등 추가 승인이 필요합니다.  
> 연습/개인 앱은 **이메일 scope 요청하지 않음** (KOE205 방지). 사용자 식별은 `kakao:{회원번호}`.

> **Client Secret이 안 보일 때** (2025.12 UI 개편): **플랫폼 키 → REST API 키** 상세 → 클라이언트 시크릿.

## 2. Auth Server 환경 변수

```bash
export KAKAO_CLIENT_ID="your-rest-api-key"
export KAKAO_CLIENT_SECRET="your-client-secret"
```

EC2:

```bash
kubectl apply -f k8s/auth-server-kakao.secret.yaml
kubectl rollout restart deployment/auth-server -n note
```

## 3. 흐름

```
프론트 Kakao 클릭
  → GET /api/auth/social/prepare/kakao (BFF)
  → Auth /auth/social/prepare/kakao → /oauth2/authorization/kakao
  → 카카오 로그인
  → SPA /oauth/callback?code&state
  → POST /api/auth/token → access_token
```

## 4. principal 이름

- 기본(이메일 미사용): `kakao:{카카오회원번호}`
- 나중에 `account_email` 승인·scope 추가 시: 이메일로 principal 가능

`CustomUserDetailsService`는 username 기준으로 테스트 유저를 생성하므로 SNS도 동일하게 동작.
