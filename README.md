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
