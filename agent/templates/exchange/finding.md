---
schema_version: 1
kind: finding
version_id: CURRENT_TRACK_VERSION
repo_commit: FULL_GIT_COMMIT_SHA
title: "발견한 취약점의 구체적인 내용"
finding_of: "H-서버가-발급한-ID"
file_path: "fs/nfsd/nfs4proc.c"
scope:
  - "fs/nfsd/"
code_refs:
  - "fs/nfsd/nfs4proc.c#nfsd4_open"
angle: runtime-reproduction
impact: "문제가 성립할 때 발생하는 보안 영향"
reproduction_command: "PoC를 실행해 KASAN 로그를 얻은 명령"
evidence_event_ids:
  - "지지-검증-이벤트의-64자리-ID"
poc_source: "PoC 파일의 UTF-8 원문을 JSON 문자열로 인코딩"
poc_sha256: "PoC 원문의 SHA-256"
kasan_log: "BUG: KASAN: ... 로그 원문을 JSON 문자열로 인코딩"
kasan_sha256: "KASAN 로그 원문의 SHA-256"
created_at: "YYYY-MM-DDTHH:MM:SSZ"
---

## 취약점

어떤 입력과 코드 경로에서 어떤 잘못된 동작이 발생하는지 적는다.

## 재현 및 근거

해당 커밋의 코드 위치, 입력·실행 명령, 관찰한 결과와 근거 검증 ID를 적는다. PoC와 KASAN 원문은 위 필드에 넣어야 수락된다. 가능하면 로컬 MCP의 `queue_finding`에 두 파일 경로를 전달한다.

## 영향과 한계

영향 범위와 아직 확인하지 못한 조건을 구분한다. 보고만으로 최종 확정되지 않는다.
