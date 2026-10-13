# 취약점 후보 분석 보고서

## 요약

취약점 후보의 제목과 의심되는 보안 영향을 적는다. 서버의 2 VM 검증 전에는 확인되지 않은 결과를 확정적으로 쓰지 않는다.

## 코드 근거

영향받는 KNFSD 경로(`fs/nfsd/`, `fs/nfs/`, `fs/nfs_common/`, `fs/lockd/`, `fs/exportfs/`, `net/sunrpc/` 또는 관련 의존성), 함수, 대상 커밋과 원인을 적는다.

## 재현 절차와 관찰

필요한 NFS 버전·옵션·권한, 서버·클라이언트 조건, PoC 빌드·실행 명령과 실제 관찰을 적는다. 독립 사용자 공간 C PoC를 우선 첨부하고 C가 없을 때만 Python 코드를 첨부한다. KASAN 로그가 있으면 함께 첨부하며, 없으면 없다고 적는다.

## 영향과 미확인 사항

KASAN read/write, controlled read/write, LPE, RCE, info leak 중 직접 확인한 것과 추정한 것을 구분한다. CVE와 관리 번호는 추정해 넣지 않는다.

로컬 MCP의 `submit_vulnerability`에 이 보고서를 `report` 문자열 또는 `kind: "report"` 파일로 전달하고, PoC·로그는 `files`에 각각 `kind: "poc"`, `kind: "log"`로 전달한다. 파일 경로는 커널 체크아웃 또는 에이전트 `runtime/evidence/` 안에 둔다. 확인된 옵션·권한·NFS 버전·취약점 유형·발견일은 `metadata`에 넣는다. 응답의 `submission_id`와 `status`를 확인한다.
