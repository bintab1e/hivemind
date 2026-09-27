# 팀 분석 현황 — <project-id>

> 서버가 생성하는 보고서 형식 예시다. 에이전트가 직접 수치를 입력하지 않는다.

- 대상: `knfsd`
- 버전: `<version-id>`
- 저장소 커밋: `<full-commit-sha>`
- 생성 시각(UTC): `<timestamp>`
- 보고한 에이전트: `<received>/<expected>`
- 마지막 수집 지연: `<duration>`

## 코드 열람 범위

| 지표 | 값 |
| --- | ---: |
| 팀이 직접 읽은 줄 / 대상 줄 | `<union-read-lines>/<eligible-lines>` |
| 팀 열람률 | `<percent>` |
| 두 명 이상이 읽은 줄 | `<overlap-lines>` |
| 직접 열람이 관측되지 않은 줄 | `<unread-lines>` |
| 검색 결과에만 나타난 줄 | `<search-only-lines>` |
| 분류되지 않은 읽기 이벤트 | `<unknown-events>` |

## 에이전트별 기여

| 에이전트 | 읽은 줄 | 고유하게 읽은 줄 | 마지막 보고 |
| --- | ---: | ---: | --- |
| `<agent-id>` | `<read-lines>` | `<exclusive-lines>` | `<timestamp>` |

## 조사 진행

| 상태 | 작업 수 |
| --- | ---: |
| 완료 | `<done>` |
| 진행 중 | `<in-progress>` |
| 막힘 | `<blocked>` |
| 미시작 | `<todo>` |

작업 완료 건수는 가설의 진실성이나 분석의 충분성을 나타내지 않는다.

## 가설 검증 상태

| 상태 | 가설 수 |
| --- | ---: |
| 검증 시도 없음 | `<unverified>` |
| 단일 근거만 있음 | `<single-source>` |
| 독립 근거로 지지됨 | `<independently-supported>` |
| 지지·반박이 충돌함 | `<contested>` |
| 이전 커밋의 근거라 재확인 필요 | `<stale>` |

## 새 가설과 분석

- `<hypothesis-id>` — `<title>` · 검증 시도 `<attempts>`건 · `<status>`

## 우선 확인할 공백

- `<path>:<line-range>` — agentcov에 직접 열람 기록 없음
- `<path>` — 열람 기록은 있으나 연결된 분석·검증 기록 없음
- `<hypothesis-id>` — 독립 검증이 없거나 결론이 충돌함

서로 다른 커밋이나 변경된 작업 트리의 수치는 이 보고서의 팀 합산에서 제외하고 별도 섹션에 표시한다.
