# Naver OAuth 연동

Google/Kakao와 동일 흐름 — `provider`만 `naver`.

## 1. Naver Developers

1. [Naver Developers](https://developers.naver.com/apps/) → 애플리케이션 등록
2. **사용 API** — 네이버 로그인 선택
3. **로그인 오픈 API 서비스 환경**
   - PC 웹 — 서비스 URL·Callback URL 등록

| 환경 | Callback URL |
|------|----------------|
| 로컬 | `http://localhost:9000/authorization-api/login/oauth2/code/naver` |
| EC2 | `https://auth.{EC2_IP}.nip.io/authorization-api/login/oauth2/code/naver` |

4. **Client ID** / **Client Secret** 복사

## 2. Auth Server 환경 변수

```bash
export NAVER_CLIENT_ID="your-client-id"
export NAVER_CLIENT_SECRET="your-client-secret"
```

`launch.json` 또는 `.env.local`에 추가 (Google/Kakao와 동일).

EC2:

```bash
kubectl apply -f k8s/auth-server-naver.secret.yaml
kubectl rollout restart deployment/auth-server -n note
```

## 3. 흐름

```
프론트 Naver 클릭
  → GET /api/auth/social/prepare/naver (BFF)
  → Auth /oauth2/authorization/naver
  → 네이버 로그인
  → SPA /oauth/callback → POST /api/auth/token
```

## 4. principal 이름

- 이메일 scope 허용 시: 이메일
- 그 외: `naver:{네이버회원식별자}`

## 5. scope

기본 `name`, `email`. 이메일 제공 거부 시에도 `naver:{id}`로 로그인 가능.
