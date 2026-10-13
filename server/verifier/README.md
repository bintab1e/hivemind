# 취약점 검증 워커 배포

새 취약점 제보는 원본 보고서와 첨부를 `submissions` 대기열에 보관합니다. 웹 서버(`hivemind` 계정)는 로컬 Unix 소켓으로 작업을 전달하고, 별도 `bintable` 계정의 워커가 헤드리스 Codex 정적 검토와 격리된 QEMU 2 VM 재현을 실행합니다. 워커에는 대시보드 DB, 에이전트 토큰, 관리자 토큰을 주지 않습니다. 기존 취약점 기록과 데이터 디렉터리는 이동하거나 초기화하지 않습니다.

현재 자동 승인 범위는 **knfsd 커널 스택의 NFSv3/v4 TCP PoC에서 서버 VM이 PoC 실행 후 KASAN read/write를 기록한 경우**입니다. 정적 검토의 `likely` 판정만으로는 등록하거나 관리 번호를 발급하지 않습니다. PoC가 정상 종료했지만 서버에서 재현되지 않으면 `rejected`, 빌드·마운트·환경 문제나 증거 부족은 `needs_evidence`, 정적 판단이 불확실하거나 정리된 정보가 부족하면 `needs_review`로 남습니다. RPC/RDMA, 특수 pNFS 구성, NFS-Ganesha, libnfs, KASAN으로 입증되지 않는 논리적 취약점·LPE·RCE 등은 이 이미지로 자동 승인하지 않습니다.

승인된 제출은 `report.md`, 원본 C `poc.c`, 실제 2 VM 설정을 적은 `reproduction.md`, 관련 서버 KASAN 블록의 `kasan.log`로 정리됩니다. 보고서는 `Summary`, `Root cause`, `Reproduction environment`, `PoC`, `Impact analysis` 순서이며 `Root cause`에 고정 커밋에서 읽은 소스 조각을 넣습니다. 제출·정적 검토·VM 실행의 NFS 버전이 어긋나거나 제목·권한·취약점 유형에 근거가 부족하면 관리 번호를 발급하지 않습니다. 최종 영향 플래그는 제출자가 주장한 값 대신 서버 VM에서 확인한 KASAN Read/Write를 사용합니다. 여러 영향이 같은 관련 증거에서 확인되면 배열에 함께 기록할 수 있지만, Controlled Read/Write·LPE·RCE·Info Leak은 현 자동 검증 범위에 들어 있지 않습니다.

## 1. 호스트와 이미지 준비

두 계정이 같은 버전의 서버 코드를 읽을 수 있어야 합니다. 공용 서버에서는 기존 `hivemind` 서비스 체크아웃을 유지하고, `bintable` 계정에 코드만 별도로 체크아웃해도 됩니다. 두 체크아웃은 같은 Git 커밋으로 맞춥니다. DB·로그·원본 PoC와 Codex 로그인 상태는 Git 체크아웃에 복사하지 않습니다.

Ubuntu 24.04 관리자는 QEMU 및 이미지 빌드 도구를 설치합니다. `acl`은 웹 서버가 검증 워커에 소켓 접근권을 줄 때 필요합니다.

```bash
sudo apt-get update
sudo apt-get install -y acl qemu-system-x86 debootstrap e2fsprogs build-essential bc bison flex libssl-dev libelf-dev dwarves git python3
```

`bintable` 계정에서 `/dev/kvm`을 읽고 쓸 수 있어야 합니다. Node.js 22.13 이상과 이 계정에 로그인된 Codex CLI도 확인합니다. 웹 서버 계정에 `/dev/kvm` 접근권이나 Codex 인증 파일을 제공할 필요는 없습니다.

```bash
test -r /dev/kvm && test -w /dev/kvm
node --version
command -v codex
```

KVM 권한이 없다면 관리자가 `sudo usermod -aG kvm bintable`을 실행한 뒤 `bintable` 세션을 다시 시작합니다.

검증할 **정확한 Linux 커널 커밋의 깨끗한 체크아웃**을 준비하고, 해당 커밋으로 KASAN 커널과 공용 VM 루트 이미지를 빌드합니다. 아래 경로는 모두 실제 절대 경로로 바꿉니다. 커널 빌드는 시간이 오래 걸릴 수 있습니다.

```bash
bash server/verifier/qemu/build-kernel.sh /absolute/kernel/source /absolute/verifier-images/kernel 4
sudo bash server/verifier/qemu/build-rootfs.sh /absolute/verifier-images/rootfs.raw
```

생성되는 `kernel-info.json`의 `sourceCommit`은 서버의 해당 분석 트랙 커밋과, 각 제보의 `repo_commit`과 일치해야 합니다. `kernelSha256`과 `vmlinuxSha256`도 실행 전 실제 빌드 파일과 대조합니다. 원본 KASAN 프레임은 보통 함수명과 오프셋만 나타내므로, 같은 빌드의 DWARF `vmlinux`로 위치를 해석합니다. 불일치하거나 위치를 확인할 수 없으면 승인하지 않습니다. VM 네트워크는 두 게스트 사이의 전용 Unix 소켓이며 호스트 브리지·NAT·게스트 인터넷이 없습니다. 루트 이미지는 매 실행 시 QEMU snapshot으로 사용하고 제출된 파일은 읽기 전용 작업 디스크로 연결합니다. 상세 구성은 [QEMU README](qemu/README.md)에 있습니다.

## 2. 웹 서버에서 작업 소켓 열기

기존 `hivemind` 사용자 서비스에 다음 두 환경 변수를 추가합니다. 소켓 경로는 기존 **비공개 데이터 디렉터리 내부의 새 파일명**으로 정하고, 두 서비스에서 동일하게 설정합니다. `HIVEMIND_VERIFIER_USER`를 지정하면 서버가 부모 디렉터리의 탐색 권한과 소켓의 읽기·쓰기 권한만 `bintable`에 ACL로 부여합니다.

```ini
Environment=HIVEMIND_VERIFIER_SOCKET=/absolute/private/data-directory/verifier.sock
Environment=HIVEMIND_VERIFIER_USER=bintable
```

기존 웹 서비스가 `PrivateTmp=true`를 사용하면 일부 사용자 서비스 환경에서는 다른 UID를 위한 `setfacl`이 사용자 네임스페이스에서 실패합니다. 이 경우 해당 드롭인에 `PrivateTmp=false`도 지정하고 소켓 ACL이 `bintable`에만 `rw`를 주는지 확인합니다. 기존 계정 분리와 `NoNewPrivileges=true`는 유지합니다.

기존 `HIVEMIND_DATA_DIR`, `dashboard-auth.env`, SQLite DB 및 로그인 설정은 그대로 둡니다. 웹 서버 재시작 후 `systemctl --user status knfsd-hub`와 소켓의 ACL을 확인합니다. 이 소켓은 TCP 포트를 열지 않습니다.

## 3. `bintable` 사용자 서비스 실행

`bintable` 홈에 작업 임시 디렉터리를 만들고 접근권을 제한합니다. 커널 이미지·루트 이미지와 그 상위 경로는 `bintable`이 읽을 수 있어야 합니다. 아래 예시는 `~/.config/systemd/user/hivemind-verifier.service`에 저장합니다. 모든 경로를 실제 절대 경로로 바꾸고, 예시 문자열을 그대로 실행하지 마세요.

```bash
install -d -m 0700 /home/bintable/hv-verifier-work
install -d -m 0700 ~/.config/systemd/user
```

```ini
[Unit]
Description=Hivemind two-VM verification worker

[Service]
Type=simple
WorkingDirectory=/absolute/bintable/hivemind-checkout
ExecStart=/usr/bin/node /absolute/bintable/hivemind-checkout/server/verifier/worker.mjs
Environment=HIVEMIND_VERIFIER_SOCKET=/absolute/private/data-directory/verifier.sock
Environment=HIVEMIND_CODEX_CLI=/absolute/path/to/codex
Environment=HIVEMIND_QEMU_KERNEL=/absolute/verifier-images/kernel/arch/x86/boot/bzImage
Environment=HIVEMIND_QEMU_KERNEL_INFO=/absolute/verifier-images/kernel/kernel-info.json
Environment=HIVEMIND_QEMU_VMLINUX=/absolute/verifier-images/kernel/vmlinux
Environment=HIVEMIND_KERNEL_SOURCE=/absolute/kernel/source
Environment=HIVEMIND_QEMU_ROOTFS=/absolute/verifier-images/rootfs.raw
Environment=HIVEMIND_VERIFIER_WORK_ROOT=/home/bintable/hv-verifier-work
UMask=0077
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now hivemind-verifier
systemctl --user status hivemind-verifier
```

이 서비스에는 비밀번호나 API 키를 `Environment=`로 기록하지 않습니다. Codex CLI는 `bintable` 계정의 기존 로그인 상태를 사용합니다. 필요하다면 관리자가 `bintable`의 user manager가 로그아웃 후에도 실행되도록 `loginctl enable-linger bintable`을 적용합니다.

활성 분석 트랙의 커널 커밋이 여러 개라면 각 커밋별로 커널 소스·`bzImage`·`vmlinux`·`kernel-info.json`을 별도로 준비하고, 위 서비스를 서로 다른 이름으로 하나씩 실행합니다. 워커는 자신의 `kernel-info.json`에 적힌 전체 커밋과 일치하는 제출만 대기열에서 가져오므로, 다른 트랙의 보고를 잘못된 VM으로 검사하지 않습니다. 공용 루트 이미지와 Unix 소켓은 함께 사용할 수 있습니다.

검증 큐의 워커 ID는 호스트명, 작업 디렉터리, 커널 정보 파일 경로와 커밋으로 계산하며 서비스 재시작 후에도 유지됩니다. 같은 호스트에서 같은 커널 설정으로 워커를 병렬 실행한다면 각 서비스에 서로 다른 `HIVEMIND_VERIFIER_WORK_ROOT`를 지정하세요.

## 4. 검증과 관찰

배포 전 동일 커밋에서 다음 회귀 테스트를 실행하고, 웹 서버의 `/healthz`와 두 사용자 서비스 상태를 확인합니다.

```bash
node --test server/*.test.mjs server/public/*.test.mjs server/verifier/*.test.mjs server/verifier/qemu/*.test.mjs
python3 server/verifier/qemu/test_guest_job.py
curl -fsS http://SERVER_LAN_IP:8765/healthz
```

실제 2 VM 실행 성공 여부는 VM 이미지를 준비한 서버에서 통제된 제출로만 확인할 수 있습니다. 대시보드의 제보 상태가 `pending`에서 검증 결과로 바뀌는지 확인하고, `approved`에는 서버 VM에서 새로 생성된 KASAN 증거와 관리 번호가 함께 있어야 합니다. 기존 기록은 이 절차로 다시 검증하거나 번호를 다시 부여하지 않습니다. 검증 실패 원인은 제보 상태에 남으며 `needs_evidence`와 `needs_review`는 근거를 보완한 뒤 관리자가 재시도할 수 있습니다.
