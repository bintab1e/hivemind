# TODO

- [x] 분석 에이전트의 독립 저장소 [`hivemind-agent`](https://github.com/bintab1e/hivemind-agent)를 만들고 설치 문서를 둔다.
- [ ] 서버 코드를 별도 저장소로 옮기고 에이전트와의 호환 버전을 관리한다. 기존 통합 저장소의 중복 에이전트 코드를 정리한다.
- [x] Linux/WSL 에이전트를 한 명령으로 설치한다. 설치기는 발급된 토큰만 입력받고 기존 커널 체크아웃·서버 등록 대상 확인, 프로젝트별 Codex MCP·agentcov 훅 설정, 주기 동기화 실행까지 처리한다. 토큰을 명령 기록이나 로그에 남기지 않는다.
- [ ] agentcov와 Node.js·Python 버전을 `requirements.txt`, `package.json` 등 표준 파일에 명시·고정하고 Linux/WSL 및 Windows 새 환경에서 설치를 검증한다.
