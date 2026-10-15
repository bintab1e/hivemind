# Hivemind

NFS 보안 분석을 위한 공용 대시보드와 분석 PC용 에이전트입니다.

| 디렉터리 | 용도 |
| --- | --- |
| [server/](server/) | 대시보드·MCP API·취약점 관리·커버리지 수집 서버 |
| [agent/](agent/) | Codex/Claude 연동, AgentCov, 5분 동기화와 취약점 제출 |

## 분석 PC 설치 (Linux·WSL·macOS)

서버 관리자가 PC마다 발급한 **개별 에이전트 토큰**과 사설망 서버 주소가 필요합니다.

```bash
git clone --filter=blob:none --sparse git@github.com:bintab1e/hivemind.git
cd hivemind
git sparse-checkout set agent
HIVEMIND_ALLOW_INSECURE_LAN_HTTP=true sh agent/setup.sh http://SERVER_LAN_IP:8765 rc
```

`SERVER_LAN_IP`를 실제 서버 주소로 바꾸고 설치기의 토큰 프롬프트에 해당 PC 전용 토큰을 입력합니다. `mainline` 트랙을 사용할 때는 마지막 인수를 `mainline`으로 바꿉니다. 설치기는 Node.js 24, AgentCov, KNFSD 분석용 커널 체크아웃, 프로젝트별 Codex 훅과 MCP, 5분 동기화 서비스를 설정합니다. 설정된 커널 디렉터리에서 새 Codex 세션을 열고 프로젝트/훅을 신뢰해야 실제 코드 열람이 수집됩니다.

서버는 팀 사설망 HTTP로 제공되므로 토큰과 보고서를 전송하는 PC도 신뢰할 수 있는 네트워크에서 사용합니다. 분석 결과에는 서버가 별도로 검증하지 않은 내용을 검증 완료로 표시하지 마세요.

서버 관리 명령은 [server/manage-local.mjs](server/manage-local.mjs)에, 실행 진입점은 [server/server.mjs](server/server.mjs)에 있습니다. 런타임 데이터와 인증 정보는 저장소 외부에 보관합니다.
