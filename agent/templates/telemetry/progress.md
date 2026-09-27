---
schema_version: 1
version_id: CURRENT_TRACK_VERSION
repo_commit: FULL_GIT_COMMIT_SHA
updated_at: "YYYY-MM-DDTHH:MM:SSZ"
---

# 분석 진행 기록

작업 ID는 해당 버전의 작업 목록에서 정한다. 진행률 퍼센트는 직접 적지 않는다.

| task_id | status | 확인한 범위·근거 | 관련 가설 | 관련 이벤트 |
| --- | --- | --- | --- | --- |
| T-001 | in_progress | `fs/nfsd/`의 입력 처리 흐름 확인 중 | H-001 |  |
| T-002 | done | 재현 테스트 확인 | H-002 | `<event-id>` |

상태는 `todo`, `in_progress`, `blocked`, `done` 중 하나를 사용한다.
`done`은 이 작업을 끝냈다는 뜻이다. 관련 가설이 검증됐거나 코드에 문제가 없다는 뜻이 아니다.
