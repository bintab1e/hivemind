# Sashiko 패치 검토

패치 탭에는 `knfsd` A 관리 번호만 표시합니다. NFS-Ganesha와 libnfs 제보에는 패치를 보내지 않으므로 이 탭에서 검토하지 않습니다. A 기록에서 `.patch` 또는 `.diff`를 선택하고 활성 RC/안정 버전을 고르면, 패치는 서버의 비공개 SQLite 대기열에 저장됩니다. `bintable` 사용자 서비스가 선택한 커밋의 **임시 Git worktree**에 적용한 후 Sashiko의 `local --force-local --agent`를 실행하고, JSON 결과를 같은 취약점의 패치 내역에 기록합니다. 원본 체크아웃이나 취약점 데이터 파일은 수정하지 않습니다.

서버의 `bintable` 계정에 [sashiko-dev/sashiko](https://github.com/sashiko-dev/sashiko)를 버전을 고정해 설치하고 `sashiko`와 `sashiko-cli` 두 바이너리를 준비합니다. `Settings.toml`의 `[ai]` 공급자를 `codex-cli`로 정하면 기존 `bintable` Codex 로그인을 사용합니다. Sashiko 프로세스는 업로드된 패치 및 관련 커널 코드를 모델 공급자에게 보냅니다. 비밀번호나 인증 파일을 `Settings.toml`, Git 저장소, systemd unit에 복사하지 않습니다. Sashiko daemon, SMTP, 메일링 리스트 수집은 필요하지 않습니다.

검토 CLI는 임시 Git worktree를 현재 디렉터리로 사용해야 Codex가 신뢰하는 작업 디렉터리에서 실행됩니다. 설정 파일은 `SASHIKO_CONFIG`로 절대 경로를 넘기므로 임시 Git 트리에 복사하지 않습니다.

`hivemind-patch-review.service`의 모든 `/absolute/...` 경로를 실제 절대 경로로 바꾸고 `~/.config/systemd/user/`에 설치합니다. `HIVEMIND_VERIFIER_SOCKET`은 기존 검증 워커가 쓰는 로컬 Unix 소켓과 같아야 합니다. `HIVEMIND_PATCH_WORK_ROOT`는 `bintable` 소유의 0700 디렉터리로 둡니다. RC 및 안정 커널 체크아웃은 각각 웹 서버에 등록된 트랙 커밋과 일치해야 합니다. 일치하지 않는 작업은 큐에서 가져오지 않습니다.

```bash
install -d -m 0700 /absolute/bintable/patch-work
systemctl --user daemon-reload
systemctl --user enable --now hivemind-patch-review.service
systemctl --user status hivemind-patch-review.service
```

Sashiko 결과의 `reviewed`는 Sashiko가 높은 심각도의 지적을 보고하지 않았다는 뜻이며 패치가 완전하게 맞다는 증명은 아닙니다. `findings`이면 결과 팝업에 Sashiko의 지적을, `error`이면 적용 실패나 실행 오류를 표시합니다. 같은 패치를 같은 트랙 커밋에 다시 올리면 기존 결과로 연결되고, 오류로 끝난 검토는 재업로드 시 다시 대기열에 들어갑니다. 수정된 패치는 새 검토가 됩니다.

```bash
node --test server/patch/*.test.mjs server/patch-reviews.test.mjs
```
