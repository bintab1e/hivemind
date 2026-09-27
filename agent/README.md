# Hivemind 분석 에이전트

Linux/WSL의 knfsd 커널 Git 체크아웃에서 명령 **한 줄**로 설치합니다. 서버가 발급한 64자리 에이전트 토큰만 준비하세요. 토큰은 입력할 때 화면이나 셸 기록에 표시되지 않습니다.

```bash
curl -fsSL https://raw.githubusercontent.com/bintab1e/hivemind-agent/main/install.sh | bash
```

현재 디렉터리는 분석할 커널 소스의 Git 저장소 안이어야 합니다. 설치기는 `192.168.1.188:8765` 서버에 연결해 현재 커밋이 등록된 `rc` 또는 `mainline` 대상인지 확인합니다. 서버와 같은 내부망에서 실행하고 서버 IP를 `192.168.1.188`로 유지하세요. 사전에 필요한 도구는 `curl`과 `git`입니다. 설치기가 Node.js 24, Python 3.11, agentcov를 사용자 폴더에 설치하며 `sudo`는 사용하지 않습니다.

설치기는 이 저장소를 커널 체크아웃의 `.hivemind/agent`에 받고, agentcov와 프로젝트별 Codex 훅·MCP 설정, 분석 진행 파일, 5분 동기화 서비스를 구성합니다. WSL에서 systemd 사용자 서비스가 없으면 현재 WSL 세션의 백그라운드 프로세스로 동기화합니다. Codex를 새로 열 때 프로젝트와 훅을 신뢰해야 실제 열람 기록이 시작됩니다.

확인:

```bash
curl -fsS http://192.168.1.188:8765/healthz
systemctl --user status hivemind-agent   # systemd를 사용할 때
```

대시보드: <http://192.168.1.188:8765/>. HTTP 직접 연결은 내부망에서만 사용합니다. 토큰·대시보드 비밀번호·분석 기록이 암호화되지 않으므로 인터넷 포트 포워딩을 하지 마세요.

Windows 분석 PC 또는 수동 설치: [MANUAL.md](MANUAL.md).
