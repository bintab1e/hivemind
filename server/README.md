# Hivemind 서버 운영

Linux 서버에서 한 줄로 설치합니다. 기본 경로는 `~/Desktop/workspace/hivemind-server`입니다. 대시보드 비밀번호와 관리자 토큰은 자동 생성되며 Git에 올라가지 않습니다.

```bash
curl -fsSL https://raw.githubusercontent.com/bintab1e/hivemind-server/main/server/install.sh | bash
```

설치 후 다음 명령으로 공식 커널 Git 태그의 최신 RC·stable을 등록합니다. 서버 설정에는 분석 PC 토큰이 필요하지 않습니다.

```bash
bash ~/Desktop/workspace/hivemind-server/server/manage.sh setup
bash ~/Desktop/workspace/hivemind-server/server/manage.sh status
```

분석 PC를 연결할 때만 아래 `agent` 명령을 실행하세요. 해당 분석 PC용 토큰과 설치 명령이 출력됩니다. 팀원에게 두 값을 전달하면 그 PC에서 커널 소스·agentcov·MCP를 설치할 수 있습니다. [에이전트 안내](https://github.com/bintab1e/hivemind-agent#readme)를 참조하세요.

추가 에이전트와 릴리스 교체:

```bash
bash ~/Desktop/workspace/hivemind-server/server/manage.sh agent add jinpyo rc
bash ~/Desktop/workspace/hivemind-server/server/manage.sh agent add pc02-codex rc
bash ~/Desktop/workspace/hivemind-server/server/manage.sh agent add pc03-claude mainline
bash ~/Desktop/workspace/hivemind-server/server/manage.sh track rc
bash ~/Desktop/workspace/hivemind-server/server/manage.sh track mainline
bash ~/Desktop/workspace/hivemind-server/server/manage.sh track rc 7.3-rc4
```

새 릴리스를 등록하면 기존 에이전트의 체크아웃을 덮어쓰지 않습니다. 분석 PC에서 설치 명령을 다시 실행하면 커밋이 다른 기존 폴더 대신 `~/workspace/knfsd-<트랙>-<버전>`에 새 소스를 받습니다. 설치 경로를 직접 지정하려면 서버에서는 `HIVEMIND_SERVER_DIR`, 분석 PC에서는 `HIVEMIND_KERNEL_ROOT` 환경 변수를 설정합니다.

```bash
curl -fsS http://127.0.0.1:8765/healthz
systemctl --user status hivemind
journalctl --user -u hivemind -n 50 --no-pager
```

새 설치의 대시보드 계정은 `guest`, 비밀번호 파일은 `~/.config/hivemind/server.env`입니다. 관리자 토큰과 SQLite DB는 `server/runtime/server/`에 있습니다. 설치기는 같은 네트워크의 PC가 연결할 수 있도록 8765 포트에 바인딩합니다. 방화벽에서는 팀 내부망만 허용하고 인터넷 포트 포워딩은 하지 마세요. LAN HTTP에서는 토큰과 분석 기록이 암호화되지 않습니다. 외부망 사용 시 HTTPS나 SSH 터널을 구성하세요.

SSH 로그아웃 뒤 서비스가 종료된다면 서버에서 `sudo loginctl enable-linger "$USER"`를 한 번 실행하세요. 백업은 `systemctl --user stop hivemind` 후 `server/runtime/server/` 전체를 복사하고 다시 `systemctl --user start hivemind`를 실행하면 됩니다.
