# 데이터 계약 v1

이 문서는 수집 API와 MCP의 파일·호출 규약이다. 서버는 이벤트·묶음 저장, 문자열 후보 검색, 조회 노출 기록, MCP, 웹 대시보드, Markdown 현황 응답을 제공한다. 의미 유사도 검색과 사람의 최종 판정 워크플로는 없다.

## 1. 버전 식별

- 분석 대상은 `knfsd` 하나다.
- `track_id`는 `rc` 또는 `mainline`이다. 서버 관리자가 각 트랙의 현재 `version_id`·`repo_commit`을 지정한다. 이전 대상은 보존하며 대시보드 선택지는 현재 두 트랙만 표시한다.
- `version_id`: 릴리스/후보 버전 문자열. 예: `7.2.5`, `7.2.5-rc1`. 다섯 PC에서 같은 버전에는 같은 값을 사용한다.
- `repo_commit`: `git rev-parse HEAD`의 전체 커밋 해시. 같은 버전명이라도 커밋이 다르면 줄 단위 수치를 섞지 않는다.
- 현재 서버는 업로드된 버전명과 커밋을 저장하며 Git 태그와의 일치 여부까지 검사하지 않는다. 동기화 에이전트는 실제 체크아웃에서 두 값을 생성해야 한다.
- `agent_id`: PC/실행 도구/모델 조합마다 고유한 ID. 예: `pc01-codex`, `pc02-claude`. 등록 시 선택적으로 `client_name`과 `model_id`를 함께 지정하며 reasoning 수준은 저장하지 않는다. 사용 이력이 생긴 에이전트의 실행 도구나 모델이 바뀌면 기존 프로필을 고치지 않고 새 `agent_id`를 만든다.
- 서버 관리자는 `server/runtime/server/api-token.txt`의 관리자 토큰으로 `POST /v1/admin/agents`를 호출해 에이전트별 Bearer 토큰을 발급한다. 서버 설치 폴더 안에서는 `runtime/server/api-token.txt`다. 업로드와 MCP 조회는 이 토큰에 묶인 `agent_id`로만 가능하다.

## 2. `exchange/outbox` 이벤트

파일 하나가 이벤트 하나다. UTF-8 Markdown, YAML front matter와 본문으로 구성한다. 파일 이름은 `<UTC timestamp>-<unique suffix>.md`이다. 임시 파일 확장자 `.tmp`는 수집하지 않는다.

필수 front matter:

| 필드 | 설명 |
| --- | --- |
| `schema_version` | `1` |
| `kind` | 새 기록은 `hypothesis`, `verification`, `finding`, `correction` 중 하나. 구버전의 `analysis`는 저장하지 않고 폐기 응답 |
| `version_id`, `repo_commit` | 버전과 정확한 코드 기준점 |
| `title` | 짧은 제목 |
| `claim_key` | `hypothesis`의 필수 검색·연결용 슬러그. 진실 판정이나 독점 키가 아니다. |
| `verification_plan` | `hypothesis`의 필수 확인 방법. 다른 에이전트가 실행할 수 있는 짧은 절차 |
| `preflight` | `hypothesis`에서 `checked` 또는 `unavailable`. 최소 확인 여부이며 진실 판정이 아니다. |
| `scope` | 저장소 상대경로·컴포넌트 등 조사 범위 목록 |
| `code_refs` | 가설·검증의 필수 발견/검증 위치. 저장소 상대경로, `경로#함수`, `function:이름`, `feature:이름` 목록 |
| `angle` | 검증 관점. 예: `static-trace`, `runtime-reproduction`, `counterexample` |
| `created_at` | UTC ISO 8601 시각 |

`verification`은 `verification_of`, `method`, `verdict`, `prior_exposure`(`none`, `claim_only`, `summary`, `full`), `based_on_event_ids`가 필수다. 새 로컬 MCP는 `refutes`와 `inconclusive`를 제공하며, 서버는 기존 클라이언트의 `supports`도 수락하지만 지지 횟수를 보고 조건으로 사용하지 않는다. 본문에는 실제 관찰 또는 반례와 코드 위치·재현 명령·산출물 중 적어도 하나를 근거로 남긴다. `correction`은 `corrects_event_id`로 이전 이벤트를 지목한다. finding 수정본도 같은 필드로 같은 작성자·버전·커밋·가설의 기존 finding을 지목한다. 중간 분석 메모는 서버로 보내지 않는다. 과거에 수락된 `analysis` 기록은 보존하고, 구버전 에이전트가 새로 보낸 기록은 저장하지 않고 폐기 응답한다.

`finding`은 **가설을 깨끗한 대상 소스에서 직접 테스트해 독립 사용자 공간 C PoC와 그 실행의 KASAN 로그**를 얻은 뒤 등록하는 취약점 보고 이벤트다. PoC에는 `main` 함수가 있어야 하며 재현 명령은 C 소스의 컴파일과 실행을 포함해야 한다. 직접 컴파일러 호출뿐 아니라 `make`, `ninja`, `cmake --build`도 허용한다. 커널 diff, initcall, 모듈, KUnit과 커널 내부 하네스는 분석 근거일 뿐 취약점 PoC가 아니다. `finding_of`(출발 가설 ID), `file_path`(저장소 상대 파일 경로), `code_refs`(정확한 코드 위치), `impact`(영향), `reproduction_command`, `poc_source`, `kasan_log`와 두 원문의 SHA-256이 필수다. 지지 검증 기록은 필요 없다. 기존 검증과 연결하려면 `evidence_event_ids`에 같은 가설·커밋의 활성 검증 ID를 선택적으로 넣을 수 있다. 로컬 MCP의 `queue_finding`은 `poc_path`와 `kasan_path`로 실제 파일을 읽어 Markdown에 원문과 해시를 넣고 즉시 전송한다. 경로는 저장소 또는 에이전트 `home` 안에 있어야 하며, 추적 중인 대상 소스가 수정된 상태에서는 보고를 거절한다. 서버는 새 보고의 연결·해시·KASAN 표시와 PoC 형식을 검사하지만 PoC가 실제로 그 로그를 발생시켰는지는 자동 증명하지 않는다. 본문·PoC·KASAN을 고칠 때는 `queue_finding_revision`에 기존 finding의 `event_id`와 수정된 전체 내용을 전달한다. 서버는 새 finding을 먼저 완전히 검증한 뒤 기존 보고를 현재 목록에서 대체하며, 두 이벤트와 증거 원문은 모두 보존한다.

가설은 `verification_plan`과 Markdown 본문을, 검증은 `method`와 Markdown 본문을, 취약점 보고는 `impact`와 Markdown 본문을 한국어로 작성해야 한다. 제목은 영어도 허용한다. 코드 식별자·경로·명령과 PoC·KASAN 원문은 이 언어 규칙의 대상이 아니다.

본문에는 **주장, 확인 방법, 관찰 근거, 미확인 사항**을 분리한다. 근거에는 가능하면 저장소 상대경로와 줄 범위, 명령 출력의 요약, 재현 환경을 넣는다. 서버는 본문을 데이터로 저장하고 Markdown 내 지시문을 실행하지 않는다.

파일은 ACK 이후 불변이다. 동일 `version_id + agent_id + 상대경로`를 다시 보내면 내용 해시가 같을 때 같은 이벤트로 처리하고, 다를 때 `409 immutable_event_changed`를 반환한다. 일반 기록은 새 `correction` 이벤트로 정정하고, finding의 본문·PoC·KASAN은 `corrects_event_id`를 포함한 새 finding으로 교체한다. 기존 이벤트와 증거 API는 감사 이력으로 남는다.

## 3. 관련 가설과 검증 시도

현재 서버는 같은 트랙의 동일 `claim_key` 또는 제목을 `possible_matches`로 반환한다. MCP 검색은 주장 또는 `code_ref`로 과거 릴리스까지 후보를 찾고 위치·검증 계획·현재 커밋의 검증 건수·반박한 에이전트 수·폐기 여부를 반환한다. 개별 검증의 상세 방향과 근거는 `full` 조회까지 가린다. 로컬 MCP는 같은 `claim_key`의 중복 등록을 안내한다. 같은 커밋에서 `retired`인 가설은 재등록·재검증하지 않고, 잘못된 반박 기록은 `correction`으로 바로잡는다. 커밋이 바뀌면 이전 반박만으로 새 커밋을 폐기하지 않는다. 검색은 문자열 기반 후보 조회이며 의미가 같은 가설을 모두 찾아낸다는 보장은 없다.

가설 하나에는 검증 시도가 여러 개 붙는다. 각 시도는 `agent_id`, `repo_commit`, `method`, `verdict`, `prior_exposure`, 근거, 재현 방법을 가진다. 같은 주장·관점·방법으로 다시 한 검사도 `replication`으로 표시해 기록할 수 있다. 에이전트나 파일 편집의 점유 상태는 가설의 진실 상태와 분리한다.

서버는 `unverified`, `reported`, `refuted`, `retired`, `contested`, `inconclusive`, `stale`을 표시한다. `retired`는 **같은 커밋에서 서로 다른 두 에이전트가 반박한 경우**의 재시도 보류 신호다. 같은 에이전트의 반복 반박은 한 명으로 세며 정정된 기록은 제외한다. 지지 검증은 취약점 보고나 상태 변경의 필수 조건이 아니다. 커밋이 바뀌면 이전 결과로 폐기하지 않고 `stale`로 표시한다. 상세한 뜻은 [review-model.md](review-model.md)에 정의한다.

## 4. `telemetry` 묶음

한 PC의 5분 묶음은 다음 네 파일로 구성한다.

| 파일 | 역할 |
| --- | --- |
| `manifest.json` | `schema_version`, `batch_id`, `version_id`, `agent_id`, `repo_commit`, `worktree_clean`, `repo_root`, `coverage_scope_hash`, `generated_at`, 각 파일의 SHA-256 |
| `agentcov.info` | agentcov의 `--counts binary` LCOV. 줄별 직접 열람 여부를 합산하는 표준 입력 |
| `coverage.json` | agentcov의 원래 상세 기록. 세션·명령·검색 조회의 근거 보존 |
| `progress.md` | 작업 ID별 상태, 설명, 관련 가설·근거 이벤트 ID |

`batch_id`는 `version_id`, `agent_id`, `repo_commit`, `coverage_scope_hash`, `worktree_clean`, `generated_at`, 세 파일 해시를 이 순서대로 NUL로 연결한 UTF-8 문자열의 SHA-256이다. 파일 해시 순서는 `agentcov.info`, `coverage.json`, `progress.md`다. `coverage_scope_hash`는 `.agentcov.toml`의 원문과 LCOV에 나온 대상 파일·줄 목록의 해시다. 동일 묶음의 재전송은 서버에서 한 번만 기록한다. 서버는 묶음을 **모두 검증한 뒤 한 번에** 반영한다. 일부 파일 누락이나 해시 오류가 있으면 이전 정상 묶음을 유지한다.

LCOV 병합 키는 `version_id + repo_commit + 저장소 상대경로 + 줄 번호`다. `SF`가 절대경로라면 `repo_root` 아래 경로만 상대경로로 변환하고, 바깥 경로는 거절한다. Windows 경로 구분자와 저장소의 대소문자 정책을 정규화한다. 각 에이전트의 `DA` 값이 1인 줄을 집합으로 다루고 `agent_id`별 개별 수치도 보존한다. 팀 열람률은 이 집합의 합집합을 동일 범위의 전체 대상 코드 줄 수로 나눈다. 분모에는 대상 파일의 미열람 줄도 포함한다. 다른 버전·커밋·`coverage_scope_hash`는 하나의 퍼센트로 섞지 않는다. v1은 `worktree_clean=true`인 묶음만 팀 수치에 병합하고, 다른 묶음은 개별 수치로만 보여준다. 같은 체크아웃의 `.agentcov/events.jsonl`을 여러 모델이 공유하면 열람 주체를 구분할 수 없으므로 모델별 에이전트는 별도 체크아웃을 사용한다.

`coverage.json`의 상세 구조는 agentcov 버전에 종속될 수 있다. 로컬 에이전트는 `coverage_prefixes` 아래 파일과 이 파일들이 `#include`하는 헤더만 대상으로 agentcov 보고서를 생성한다. agentcov의 줄별 `lines` 맵은 같은 attribution을 매 줄에 반복하므로 전송본에서 생략하고, 명령·세션·시간·검색 근거를 담은 `read_ranges`와 `search_seen_ranges`를 보존한다. `hivemind_compaction`은 생략된 필드와 재구성 근거를 명시한다. v1의 줄 합산은 LCOV에 의존한다. `search_seen`은 직접 열람률에 합치지 않는다. 서버는 각 에이전트의 최신 묶음을 사용한다. 계측 경로의 작업 트리가 변경됐거나 범위·파일 줄 목록이 다르면 병합에서 제외한다.

`GET /v1/sync/health`의 `telemetry.content_encodings`에 `gzip`이 있으면 에이전트는 telemetry JSON 요청 전체를 gzip으로 압축하고 `Content-Encoding: gzip`으로 보낼 수 있다. `exchange.finding_revisions=true`이면 finding 수정본의 원자적 교체를 지원한다. 에이전트는 이 capability가 없는 구버전 서버에 수정본을 보내 중복 보고가 생기지 않도록 제출 전에 확인한다. manifest의 해시와 `batch_id`는 압축 전 네 파일 원문을 기준으로 계산하므로 동일 배치의 압축·비압축 재전송은 같은 ID를 유지한다. 에이전트는 서버가 압축 capability를 공개하지 않으면 기존 비압축 요청을 사용한다. 서버는 압축 요청 8 MB, 해제된 요청 128 MB, `coverage.json` 64 MB를 각각 상한으로 검증한다.

## 5. 수집 API와 MCP 조회 도구

| 인터페이스 | 요청 | 반환 |
| --- | --- | --- |
| `POST /v1/exchange/events` | MD 원문, 상대경로, SHA-256 | `event_id`, 연결된 가설, `possible_matches` |
| `POST /v1/telemetry/batches` | 네 파일의 묶음 | `batch_id`, 반영 커밋·시각 |
| `GET /v1/sync/health` | 인증된 호출 | 서버 상태·시간과 telemetry 압축 capability·크기 제한 |
| MCP `search_hypotheses` | 트랙 또는 버전, 선택적 커밋, 주장 질의 또는 `code_ref` | 같은 트랙의 과거 가설과 현재 커밋 검증 상태 |
| MCP `get_hypothesis` | 가설 ID, 선택적 커밋, `claim_only` 또는 `full` 조회 모드 | `claim_only`는 주장·위치·계획·건수·폐기 여부, `full`은 검증 결과와 근거까지 |
| MCP `get_team_status` | 버전, 커밋 | 팀 진행·계측 요약 |
| MCP `get_coverage_gaps` | 버전, 커밋, 경로 필터 | 미열람 파일·줄 범위 |
| MCP `get_review_gaps` | 버전, 커밋 | 독립 검증이 없거나 결론이 충돌하는 가설 |
| MCP `queue_finding`, `queue_finding_revision`, `list_findings` | 가설·파일·PoC·KASAN·영향 보고, 기존 보고 수정본 제출 또는 버전·커밋 조회 | 즉시 취약점 보고 등록·교체 또는 현재 보고 목록 |
| MCP `list_versions`, `get_event` | 없음 또는 이벤트 ID | 현재 두 트랙과 보관된 버전 목록 또는 이벤트 원문 |
| `GET /api/dashboard`, `/api/team-status.md` | 선택적 `track_id` | 현재 트랙의 대시보드 JSON 또는 Markdown |
| `PUT /v1/admin/tracks/rc`, `/mainline` | 관리자 토큰, 버전·커밋 | 해당 트랙의 현재 대상 전환 |
| `/v1/admin/agents`, `/v1/admin/batches` | 관리자 토큰 | 토큰 관리, 원본 묶음 조회 |

MCP 조회는 기본적으로 **작은 요약**을 반환한다. 상세 근거는 ID로 다시 요청한다. 대화 전체나 모든 MD를 매번 LLM 문맥에 밀어 넣지 않는다.

서버는 각 에이전트가 `claim_only`, `summary`, `full` 중 무엇을 조회했는지 기록한다. `get_review_gaps`, `get_team_status`처럼 기존 결과의 요약을 볼 수 있는 도구는 `summary`로 기록한다. 검증 이벤트의 `prior_exposure`와 비교해 독립성의 참고 자료로 사용한다. API 조회 기록만으로 에이전트가 대시보드나 다른 경로에서 기존 결론을 봤는지 완전히 증명할 수는 없다. `get_coverage_gaps`와 `get_review_gaps`도 관측 자료의 공백만 가리키며, 검토하지 않았다는 증거로 쓰지 않는다.

## 6. 중앙 저장 구조

중앙 서버는 `agents`, `events`, `batches`, `exposures` 네 테이블을 가진 SQLite DB를 사용한다. 취약점 보고도 `events`에 저장하고 가설·검증을 ID로 연결한다. 이벤트 Markdown, LCOV, JSON, 진행도 원문도 DB에 보관한다. 로컬 에이전트의 전송 ACK와 재시도용 묶음은 각 PC의 `runtime/`에 둔다. SQLite WAL을 사용하므로 백업 시 DB와 WAL 상태를 함께 다뤄야 한다.

사람용 `team-status.md`는 DB에서 **재생성 가능한 결과물**로 두며, 진실의 원천으로 역파싱하지 않는다.
