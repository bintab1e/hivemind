# knfsd Hivemind Server

여러 분석 PC의 knfsd 가설·검증·PoC/KASAN 보고와 [agentcov](https://github.com/trailofbits/agentcov) 열람 기록을 받는 중앙 서버입니다. 웹 대시보드, MCP 조회 API, SQLite 저장소가 포함됩니다. 분석 PC에 설치하는 코드는 별도 저장소 [`hivemind-agent`](https://github.com/bintab1e/hivemind-agent)에 있습니다.

```text
server/server.mjs       HTTP API·SQLite·대시보드 서버
server/contract.mjs     이벤트·커버리지 입력 검증
server/public/          웹 대시보드
server/README.md        Linux 설치·서비스·토큰 발급 안내
docs/                   서버 데이터 계약·검증 모델
server.test.mjs         서버 API 통합 검사
```

## Linux 서버 설치

Node.js 24 이상과 Git이 필요합니다. 서버에는 agentcov나 커널 소스를 설치할 필요가 없습니다.

```bash
git clone https://github.com/bintab1e/hivemind-server.git "$HOME/hivemind-server"
cd "$HOME/hivemind-server/server"
node --version
node server.mjs
```

다른 터미널에서 `curl -fsS http://127.0.0.1:8765/healthz`로 확인합니다. systemd 상시 실행, 내부망 접속, RC·mainline 등록, 팀원별 토큰 발급은 [서버 설치 안내](server/README.md)에 명령어로 정리했습니다.

기존 `~/Desktop/workspace/hivemind` 체크아웃을 계속 쓰는 서버라면 설치 경로를 옮길 필요가 없습니다.

```bash
cd "$HOME/Desktop/workspace/hivemind"
git remote set-url origin https://github.com/bintab1e/hivemind-server.git
git pull --ff-only
systemctl --user restart hivemind
curl -fsS http://127.0.0.1:8765/healthz
```

서버의 데이터와 관리자 토큰은 `server/runtime/server/`에 저장되며 Git에서 제외됩니다. 분석 PC에는 [`hivemind-agent` 설치 안내](https://github.com/bintab1e/hivemind-agent#readme)를 전달하세요.

## 개발 확인

```bash
node --test server.test.mjs
```

기록 형식과 집계 규칙: [데이터 계약](docs/data-contract.md) · [검증 모델](docs/review-model.md) · [아키텍처](docs/architecture.md).
