# secure-coding

Tiny Second-hand Shopping Platform - WHS 4기 시큐어코딩 강의 과제

## 환경 설정

```
git clone https://github.com/kokokyng/secure-coding.git
cd secure-coding
conda env create -f enviroments.yaml
conda activate secure_coding
```

## 실행 방법

```
python app.py
```

실행 후 브라우저에서 http://localhost:5000 접속.

외부 기기에서 테스트하려면 ngrok으로 포워딩할 수 있습니다.

```
# optional
sudo snap install ngrok
ngrok http 5000
```

## 기본 관리자 계정

최초 실행 시 관리자 계정이 자동으로 생성됩니다.

- 아이디: `admin`
- 비밀번호: `admin1234!`

실서비스 환경에서는 반드시 비밀번호를 변경해야 합니다.

## 구현된 기능

- 회원가입 / 로그인 / 로그아웃
- 프로필 조회, 소개글 및 비밀번호 변경
- 상품 등록 / 조회 / 검색 / 수정 / 삭제 (소유자만 수정·삭제 가능)
- 유저 간 송금 및 송금 내역 조회
- 전체 실시간 채팅 및 1:1 채팅
- 신고 기능 및 신고 누적 시 자동 차단(상품)/휴면(유저) 처리
- 관리자 대시보드 (유저 상태 관리, 상품 강제 삭제, 신고 처리)

## 보안 강화 사항

- 비밀번호 해시 저장 (werkzeug `generate_password_hash`/`scrypt`), 기존 평문 비밀번호 자동 마이그레이션
- 모든 상태 변경 요청(POST)에 CSRF 토큰 검증 적용
- 로그인 5회 실패 시 5분간 계정 잠금
- 세션 쿠키 HttpOnly/SameSite=Lax 설정, 세션 만료(30분), 로그인 시 세션 재발급(session fixation 방지)
- 송금 시 비밀번호 재인증 요구
- 신고 남용 방지 (동일 대상 중복 신고 차단, 서로 다른 신고자 수 기준으로 임계치 판단)
- 서버측 입력 길이/형식 검증 (사용자명, 비밀번호, 상품 정보, 신고 사유, 채팅 메시지 등)
- Jinja2 자동 이스케이프 + 클라이언트 `textContent` 사용으로 XSS 방어
- Socket.IO 연결 시 로그인 여부 확인, 발신자 정보는 클라이언트 입력이 아닌 서버 세션에서 조회, 메시지 Rate Limiting 적용
- 보안 헤더 적용 (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- 404/500 에러 시 스택 트레이스 등 내부 정보 노출 없이 일반 메시지만 표시, `debug=False` 기본값
- DB 파일 권한을 소유자 전용(600)으로 제한

프로덕션 배포 시에는 `SECRET_KEY`, `SESSION_COOKIE_SECURE=1` 환경변수를 설정하고 HTTPS와 프로덕션급 WSGI 서버(gunicorn/eventlet 등) 뒤에서 서비스해야 합니다.
