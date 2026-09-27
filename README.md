# knfsd Hivemind Server

가설·반박·PoC/KASAN 보고와 agentcov 코드 열람 기록을 모으는 Linux 중앙 서버입니다. 분석 PC에는 별도 [`hivemind-agent`](https://github.com/bintab1e/hivemind-agent)를 설치합니다.

## 1. Linux 서버 PC

다음 한 줄이 저장소, Node.js 24, 웹 대시보드와 사용자 systemd 서비스를 설치합니다. Git·curl·xz가 없으면 Ubuntu/Debian에서 설치를 시도합니다.

```bash
curl -fsSL https://raw.githubusercontent.com/bintab1e/hivemind-server/main/server/install.sh | bash
```

최신 RC와 stable의 공식 커널 Git 태그를 조회해 두 분석 대상을 등록합니다. 서버 설정에는 분석 PC 토큰이 필요하지 않습니다.

```bash
bash "$HOME/Desktop/workspace/hivemind-server/server/manage.sh" setup
```

분석 PC를 연결할 때만 `bash "$HOME/Desktop/workspace/hivemind-server/server/manage.sh" agent add jinpyo rc`를 실행하세요. `jinpyo`를 지정한 에이전트 이름으로 바꾸면 **해당 에이전트용 토큰**과 **분석 PC 설치 명령**이 출력됩니다. 토큰은 그 분석 PC에만 전달합니다. 대상 갱신은 `.../manage.sh track rc` 또는 `.../manage.sh track mainline`입니다.

서버 설치기가 대시보드 주소와 `viewer` 비밀번호도 출력합니다. 상태 확인은 `curl -fsS http://127.0.0.1:8765/healthz`, 로그 확인은 `journalctl --user -u hivemind -f`입니다.

## 2. Linux/WSL 분석 PC

서버에서 출력한 설치 명령을 분석 PC에서 실행하고 토큰을 한 번 입력합니다. 예:

```bash
curl -fsSL https://raw.githubusercontent.com/bintab1e/hivemind-agent/main/install.sh | bash -s -- http://192.168.1.188:8765 rc
```

설치기는 등록된 커널 태그를 `~/workspace/knfsd`에 내려받아 서버의 SHA와 비교하고, 에이전트 코드·agentcov·Codex 프로젝트 MCP·5분 동기화를 설정합니다. 기존 커널 체크아웃이 있다면 SHA가 일치할 때만 사용합니다. 설치 후 그 커널 폴더에서 새 Codex 세션을 열어 프로젝트와 훅을 신뢰하세요. 분석 PC 세부 안내: [hivemind-agent README](https://github.com/bintab1e/hivemind-agent#readme).

## 가설 처리

LLM이 가설을 등록하면 직접 테스트할 수 있습니다. PoC와 그 실행의 KASAN 로그가 있으면 **지지 검증 기록 없이 바로 취약점 보고**를 보냅니다. 반례를 찾으면 `refutes` 검증을 보냅니다. 같은 커밋에서 서로 다른 에이전트 두 명의 반박이 쌓이면 해당 가설은 재시도 보류 상태가 됩니다. 같은 에이전트의 반복 기록은 한 명으로 셉니다. 과거 검증과 보고는 삭제되지 않으며, 새 커밋에서는 상태를 다시 계산합니다.

커버리지는 agentcov가 관측한 **코드 열람률**입니다. 가설의 참·거짓이나 분석 완료율을 뜻하지 않습니다.

개발 확인: `node --test server.test.mjs server/manage.test.mjs`. 자세한 서버 명령은 [server/README.md](server/README.md), 입력 형식은 [데이터 계약](docs/data-contract.md)을 보세요.
