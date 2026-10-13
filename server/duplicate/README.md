# 매일 중복 검사

`bintable` 사용자 서비스가 매일 **06:00 Asia/Seoul**에 한 번 실행됩니다. 웹 서버의 전용 Unix 소켓에서 `제보 완료`·`중복`·`철회`를 제외한 기존/신규 기록을 읽고, 공개 메일과 프로젝트 유지관리 브랜치의 패치 본문을 비교합니다. 확인된 동일 원인에만 `중복`을 적용합니다. 과거 기록의 상태가 비어 있으면 근거를 기록하되 상태는 변경하지 않습니다.

공식 소스는 Linux NFSD의 [linux-nfs 메일](https://lore.kernel.org/linux-nfs/)·[Patchwork](https://patchwork.kernel.org/project/linux-nfs/list/)와 [NFSD maintainer tree](https://git.kernel.org/pub/scm/linux/kernel/git/cel/linux.git/), NFS-Ganesha의 [devel archive](https://lists.nfs-ganesha.org/archives/list/devel@lists.nfs-ganesha.org/)·[next branch](https://github.com/nfs-ganesha/nfs-ganesha/tree/next), libnfs의 [mail group](https://groups.google.com/g/libnfs)·[master branch](https://github.com/sahlberg/libnfs)입니다. 최근 자료와 공개 코드 식별자에 의한 과거 검색을 병행합니다. 아카이브의 검색 범위와 결과 수에는 한계가 있으므로 무매치는 전체 과거의 중복 부재를 확정하지 않습니다.

공개 검색 URL에는 분석 보고서·비공개 제목·PoC를 넣지 않고, 보고서에서 추출한 공개 소스 파일명이나 함수명만 사용합니다. 후보 보고서는 서버의 `bintable` 계정에서 실행하는 헤드리스 Codex에 입력되며, Codex 검토를 위해 해당 내용이 Codex 서비스로 전송됩니다. 외부 자료와 보고서를 작업 디스크에 캐시하지 않으며 서비스 로그는 집계 수만 출력합니다. Codex는 도구와 네트워크를 끈 구조화 출력 모드로 실행됩니다. 메일 또는 브랜치가 조회되지 않으면 상태를 바꾸지 않고 오류를 기록합니다.

기존 검증 워커의 웹 서버 소켓 설정과 `bintable` 계정 Codex 로그인 상태를 재사용합니다. 두 계정의 서버 코드 커밋을 맞춘 뒤 다음 사용자 서비스 템플릿에서 `/absolute/...`를 실제 경로로 바꾸세요. `HIVEMIND_DUPLICATE_WORK_ROOT`는 `bintable` 소유 0700 디렉터리여야 합니다. API 키나 비밀번호를 unit에 기록하지 않습니다.

```bash
install -d -m 0700 /home/bintable/hv-verifier/work-duplicate
install -m 0600 server/duplicate/hivemind-duplicate-check.service ~/.config/systemd/user/
install -m 0600 server/duplicate/hivemind-duplicate-check.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemd-analyze calendar '*-*-* 06:00:00 Asia/Seoul'
systemctl --user enable --now hivemind-duplicate-check.timer
systemctl --user list-timers --all hivemind-duplicate-check.timer
```

첫 동작을 확인하려면 `systemctl --user start hivemind-duplicate-check.service`를 실행하세요. 현황은 `systemctl --user status hivemind-duplicate-check.service`와 `journalctl --user -u hivemind-duplicate-check.service`에서 집계로 확인합니다. 외부 소스 장애가 있으면 oneshot 서비스가 실패하고 다음 날 타이머가 다시 시도합니다. 반복된 실패는 `/duplicate/result`의 검사 기록에서 원인을 확인해야 합니다.

```bash
node --test server/duplicate/*.test.mjs
```
