---
schema_version: 1
kind: verification
version_id: CURRENT_TRACK_VERSION
repo_commit: FULL_GIT_COMMIT_SHA
title: "기존 가설의 독립 검증 결과"
verification_of: "H-서버가-발급한-ID"
scope:
  - "fs/nfsd/"
code_refs:
  - "fs/nfsd/nfs4proc.c#nfsd4_open"
angle: runtime-reproduction
method: "경계값 입력으로 독립 재현"
verdict: inconclusive
prior_exposure: claim_only
based_on_event_ids: []
created_at: "YYYY-MM-DDTHH:MM:SSZ"
---

## 내가 검증한 주장

기존 가설 중 실제로 검사한 조건과 예상 결과를 적는다.

## 수행한 검증

- 현재 커밋에서 확인한 코드 위치:
- 입력·환경·실행 명령 또는 정적 추적 경로:
- 기존 분석과 다른 검증 방법 또는 독립적으로 확인한 부분:

## 관찰 결과

도구 출력이나 재현 결과를 요약하고 원본 산출물 위치를 남긴다.

## 판정과 한계

`supports`, `refutes`, `inconclusive` 중 하나를 선택한 이유와 아직 확인하지 못한 조건을 적는다. 기존 결론을 봤다면 언제, 어느 범위까지 봤는지 적는다.
