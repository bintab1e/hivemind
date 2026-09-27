---
schema_version: 1
kind: hypothesis
version_id: CURRENT_TRACK_VERSION
repo_commit: FULL_GIT_COMMIT_SHA
title: "짧고 검증 가능한 가설"
claim_key: "example-input-validation-bypass"
related_hypothesis_id: null
preflight: checked
verification_plan: "경계 입력으로 해당 분기를 재현하고 예상 결과와 비교한다"
scope:
  - "fs/nfsd/"
code_refs:
  - "fs/nfsd/nfs4proc.c#nfsd4_open"
angle: static-trace
created_at: "YYYY-MM-DDTHH:MM:SSZ"
---

## 주장

어떤 입력·상태에서 무엇이 잘못될 수 있는지 한두 문장으로 적는다.

## 근거와 배경

관찰한 코드 위치와 확인한 사실을 적는다. 파일 대신 기능에서 출발했다면 `function:이름` 또는 `feature:이름`을 `code_refs`에 넣는다. 추론은 관찰과 구별한다.

## 등록 전 확인

- 비슷한 기존 가설 ID와 차이:
- 현재 커밋에서 직접 확인한 코드·조건:
- 아직 재현하지 못했다면 그 이유:

`preflight`는 `checked` 또는 `unavailable`을 사용한다. 이는 기초 확인 여부일 뿐, 참·거짓 판정이 아니다.

## 검증 계획

어떤 입력, 테스트, 분석으로 가설을 지지하거나 반박할지 적는다.

## 아직 확인하지 못한 점

미확인 조건과 필요한 다른 관점을 적는다.

이 문서만으로 가설을 `참`으로 표시하지 않는다. 확인이 부족하면 `unverified` 상태로 둔다.
