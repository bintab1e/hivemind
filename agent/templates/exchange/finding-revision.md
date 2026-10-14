# 취약점 후보 정정

정정도 `templates/report.md`를 복사해 **새 `report.md`**로 제출한다. `Summary`에 이전 `submission_id`와 정정 이유를 적고, 나머지 네 절을 수정된 전체 근거로 다시 작성한다. `poc.c`, `reproduction.md` 또는 `reproduce.sh`, 실제 KASAN/KCSAN `.log`도 함께 제출한다. 이미 승인된 동일 취약점의 강화 제출이라면 대시보드의 취약점 관리에서 확인한 관리 번호를 `submit_vulnerability`의 `existing_management_id`에 넣는다. 번호가 아직 없으면 생략한다. 기존 기록은 자동으로 덮어쓰지 않으며 새 `submission_id`와 `status`를 확인한다. CVE·제보 상태를 추측하지 않는다.
