# 취약점 후보 정정

정정도 `templates/report.md`를 복사해 **새 `report.md`**로 제출한다. `Summary`에 이전 `submission_id`와 정정 이유를 적고, 나머지 네 절을 수정된 전체 근거로 다시 작성한다. `poc.c`, `reproduction.md` 또는 `reproduce.sh`, 실제 KASAN/KCSAN `.log`도 함께 제출한다. 동일 취약점의 강화 제출에는 첫 접수에서 받은 고유번호(예: `V-000001`)를 `submit_vulnerability`의 `existing_vulnerability_id`에 반드시 넣는다. 이미 승인된 기존 건의 관리번호(예: `A-005`)도 사용할 수 있다. `local_pending`이었다면 동기화 후 고유번호를 확인하고 보강 자료를 제출한다. 기존 기록은 자동으로 덮어쓰지 않으며 새 `submission_id`와 `status`를 확인한다. CVE·제보 상태를 추측하지 않는다.
