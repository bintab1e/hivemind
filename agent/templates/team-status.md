# 팀 분석 현황 — <project-id>

> 서버가 생성하는 보고서 형식 예시다. 에이전트가 수치를 직접 입력하지 않는다.

- 대상: `knfsd`
- 버전: `<version-id>`
- 저장소 커밋: `<full-commit-sha>`
- 보고한 에이전트: `<received>/<expected>`

## 코드 열람 범위

| 지표 | 값 |
| --- | ---: |
| 팀이 직접 읽은 줄 / 대상 줄 | `<union-read-lines>/<eligible-lines>` |
| 두 명 이상이 읽은 줄 | `<overlap-lines>` |
| 직접 열람이 관측되지 않은 줄 | `<unread-lines>` |

## 에이전트별 기여

| 에이전트 | 읽은 줄 | 고유하게 읽은 줄 | 마지막 보고 |
| --- | ---: | ---: | --- |
| `<agent-id>` | `<read-lines>` | `<exclusive-lines>` | `<timestamp>` |

## 검증된 취약점

| 보고 ID | 코드 위치 | 검증된 영향 | 2 VM 재현 |
| --- | --- | --- | --- |
| `<event-id>` | `<file-path>` | `<verified-impacts>` | `<status>` |

커버리지와 작업 완료율은 취약점의 존재 여부를 판정하지 않는다.
