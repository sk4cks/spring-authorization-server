# Google OAuth 연동 (로컬)

## 1. Google Cloud Console

1. [Google Cloud Console](https://console.cloud.google.com/) → 프로젝트 선택
2. **APIs & Services → OAuth consent screen** — External, 테스트 사용자에 본인 Gmail 추가
3. **Credentials → Create OAuth client ID** — Web application

| 항목 | 로컬 값 |
|------|---------|
| Authorized redirect URIs | `http://localhost:9000/authorization-api/login/oauth2/code/google` |

EC2 배포 시 추가:

```
https://auth.{EC2_IP}.nip.io/authorization-api/login/oauth2/code/google
```

## 2. Auth Server 환경 변수

```bash
export GOOGLE_CLIENT_ID="xxxx.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="GOCSPX-xxxx"
```

IDE 실행 시 Run Configuration env에 동일하게 설정.

## 3. 흐름

```
프론트 Google 클릭
  → /auth/social/prepare/google (PKCE state 저장)
  → Google 로그인
  → SPA /oauth/callback?code&state
  → POST /api/auth/token
  → access_token → sessionStorage
```

## 4. 로컬 실행

```bash
# Auth :9000
# API :8082
# 프론트 :8080
```

`.env` (react-note):

```
VITE_BASE_API_URL=http://localhost:8082
VITE_OAUTH_REDIRECT_URI=http://localhost:8080/oauth/callback
```

SNS 시작은 프론트 → `GET /api/auth/social/prepare/google` (BFF) → Auth Server.
