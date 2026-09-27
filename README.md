# knfsd Hivemind

여러 LLM의 Linux knfsd 분석에서 가설·검증·PoC/KASAN 보고와 [agentcov](https://github.com/trailofbits/agentcov)의 코드 열람 기록을 모으는 서버입니다. **서버와 분석 에이전트는 독립 설치 폴더**입니다. 두 폴더 모두 Node.js 24 이상에서 npm 설치 없이 실행됩니다.

```text
server/                         Linux 중앙 서버에 이 폴더만 설치
  server.mjs                    API·SQLite·웹 대시보드
  contract.mjs                  서버 측 기록 검증·MCP 도구 계약
  public/                       대시보드 정적 파일

agent/                          각 분석 PC에 이 폴더만 설치 (Linux / Windows)
  mcp-agent.mjs                 LLM의 stdio MCP, 가설·검증 즉시 전송
  sync-agent.mjs                outbox 재시도, agentcov·진행도 주기 전송
  contract.mjs                  서버 계약의 로컬 검증 사본
  coverage-scope.mjs            NFS 코드·include 계측 범위
  agentcov-windows-hook.py      Windows PowerShell 열람 변환
  agent.example.json            에이전트 설정 예시
  templates/                    교환·진행도 Markdown 템플릿
```

`server/`는 `agent/`에 의존하지 않고, `agent/`는 `server/`에 의존하지 않습니다. `contract.mjs`는 두 설치 폴더에 같은 내용으로 포함되며 테스트가 일치 여부를 확인합니다. 분석 PC에는 서버 코드·DB를 복사하지 않고, 서버에는 커널 체크아웃·agentcov를 설치하지 않습니다. 각 LLM에는 고유 ID·토큰·커널 체크아웃·agentcov 저장소를 사용합니다.

## 설치 순서

1. **Linux 서버:** [`server/README.md`](server/README.md)에 따라 `server/` 폴더만 복사하고 systemd 서비스를 시작합니다.
2. **첫 분석 PC:** [`agent/README.md`](agent/README.md)의 Linux 또는 Windows 절차로 커널 소스를 받아 전체 커밋 SHA를 확인합니다.
3. **Linux 서버:** `rc`, `mainline`(stable) 대상의 버전·SHA를 등록하고 LLM마다 토큰을 발급합니다.
4. **Linux/WSL 분석 PC:** 커널 Git 체크아웃에서 [`hivemind-agent`](https://github.com/bintab1e/hivemind-agent)의 원라인 설치 명령을 실행하고 발급된 토큰을 입력합니다. 설치기가 agentcov, stdio MCP, 동기화 에이전트를 설정합니다.

새 분석 PC는 독립 에이전트 저장소를 사용합니다. 현재 이 저장소의 `agent/`는 기존 설치와 통합 테스트를 위한 사본이며, 서버 저장소 분리 후 정리할 예정입니다. 서버 폴더만 받을 때는 Git sparse checkout을 사용할 수 있습니다.

```bash
git clone --filter=blob:none --no-checkout HIVEMIND_REPO_URL hivemind-source
cd hivemind-source
git sparse-checkout init --no-cone
git sparse-checkout set '/server/**'
git checkout
```

이때 `hivemind-source/server/`를 서버 설치 폴더로 사용합니다. 각각의 `runtime/`과 에이전트 `.venv/`는 Git에서 제외됩니다. 관리자 토큰·에이전트 토큰·SQLite DB를 GitHub에 올리지 마세요. 현재 작업 폴더가 아직 Git 저장소가 아니라면 먼저 GitHub 저장소를 만들고 두 폴더와 이 README를 올립니다.

## 실행 확인

```bash
node --test server.test.mjs mcp-agent.test.mjs packages.test.mjs
node local-demo.mjs --once --port=0
```

`packages.test.mjs`는 `server/`와 `agent/`를 각각 독립 디렉터리에 복사해서 웹 서버와 MCP 조회를 시험합니다. `local-demo.mjs`는 합성 데이터로 여러 에이전트의 기록 흐름을 점검합니다. 둘 다 실제 커널 취약점 재현을 뜻하지 않습니다.

## 분석 흐름

1. **코드를 읽고 후보 검색:** 현재 커밋의 파일·함수·기능을 확인한 뒤 `search_hypotheses`에 주장이나 `code_ref`를 넣습니다. 같은 가설을 찾았다는 사실은 참·거짓의 증거가 아닙니다.
2. **가설 등록:** 새 주장이라면 `queue_hypothesis`에 `claim_key`, `code_refs`, `verification_plan`, 확인한 근거와 미확인 조건을 적습니다. 기존 주장과 같다면 새 가설 대신 기존 ID를 검증합니다.
3. **독립 검증:** 가능하면 `get_hypothesis`의 `claim_only`로 주장만 보고 현재 커밋의 코드를 직접 조사합니다. `queue_verification`에 `verification_of`, `method`, `prior_exposure`, `supports`·`refutes`·`inconclusive` 중 하나와 실제 근거를 남깁니다. 두 독립 반박이 쌓이면 가설은 `retired`가 될 수 있지만, 새 근거가 있으면 재검증할 수 있습니다.
4. **취약점 보고:** 해당 커밋의 지지 검증 이벤트가 있고, **실제 PoC 파일과 그 실행으로 얻은 `BUG: KASAN:` 로그**가 있을 때만 `queue_finding`을 사용합니다. `finding_of`, `file_path`, `evidence_event_ids`, 영향, 재현 명령, `poc_path`, `kasan_path`가 필요합니다. 대시보드에서 PoC와 KASAN 원문을 열어볼 수 있습니다.
5. **기록 정정:** 수락된 Markdown은 수정하지 않고 `queue_correction`으로 정정 이벤트를 추가합니다.

`queue_*`는 로컬 `agent/runtime/exchange/outbox/<agent-id>/`에 Markdown을 만들고 즉시 전송합니다. 응답의 `accepted: true`와 `event_id`를 확인하세요. `accepted: false`는 아직 서버에 반영되지 않은 로컬 기록입니다. MCP를 사용할 수 없으면 [교환 템플릿](agent/templates/exchange/)으로 새 Markdown 파일을 만듭니다.

## 대시보드 읽기

| 메뉴 | 표시 내용 |
| --- | --- |
| 분석 현황 | 트랙의 현재 버전·커밋, 에이전트, 관측 열람률, 진행도 |
| 전체 코드 커버리지 | 팀 합집합 또는 에이전트별 파일·줄 열람, 경로 필터 |
| 가설·검증 | 가설을 선택해 연결된 검증 기록과 상태 확인 |
| 취약점 보고 | 가설·발견 파일·보고 에이전트와 PoC·KASAN 열람 |

**관측 열람률은 LLM이 도구로 읽은 소스 줄의 비율**입니다. 테스트 실행 커버리지, 코드 이해도, 분석 완료율이 아닙니다. sparse checkout에 없거나 빌드 시 생성되는 헤더는 `미확인 include`로 남습니다. 정적 `#include` 관계만으로 knfsd의 모든 런타임 호출 경로를 보장하지 않습니다. 서버는 PoC·KASAN 파일의 존재·해시·KASAN 표식을 검사하지만, 로그가 그 PoC 실행에서 생겼다는 사실까지 자동 증명하지는 않습니다.

## 릴리스 교체와 시험

새 RC 또는 stable이 나오면 **새 체크아웃**을 만들고 `PUT /v1/admin/tracks/rc` 또는 `/mainline`으로 버전·커밋을 갱신합니다. 각 에이전트 설정과 진행도 파일을 새 대상에 맞춘 뒤 MCP·동기화 프로세스를 재시작합니다. 기존 체크아웃의 커밋만 바꾸면 agentcov 기록이 섞일 수 있어 업로드가 차단됩니다. 과거 기록은 보존되고 새 커밋의 열람률은 새로 계산됩니다.

agentcov까지 포함한 전체 모의 운영 검사는 개발용 저장소 루트에서 실행합니다.

```bash
AGENTCOV_BIN="$HOME/hivemind-agent/.venv/bin/agentcov" node pipeline-smoke.mjs
```

`local-demo.mjs`는 합성 코드로 5개 MCP 에이전트의 가설·검증·보고와 커버리지 병합을 확인합니다. `pipeline-smoke.mjs`는 설치된 agentcov와 독립 체크아웃 5개의 전송·서버 재시작을 검사합니다. 둘 다 격리 서버를 사용하며 실제 커널 취약점 발견이나 KASAN 재현을 뜻하지 않습니다.

설계와 데이터 형식: [아키텍처](docs/architecture.md) · [기록 계약](docs/data-contract.md) · [검증 모델](docs/review-model.md) · [분석 LLM 지침](docs/agent-instructions.md).
