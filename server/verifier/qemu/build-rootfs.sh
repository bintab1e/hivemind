#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo "usage: sudo $0 /absolute/path/to/rootfs.raw" >&2
  exit 2
fi
if (( EUID != 0 )); then
  echo "root is required for debootstrap; do not run submitted PoCs here" >&2
  exit 2
fi
for tool in debootstrap mkfs.ext4 truncate; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
target="$1"
[[ "$target" = /* && ! -e "$target" ]] || { echo "output must be a new absolute path" >&2; exit 2; }
mkdir -p "$(dirname "$target")"
work="$(mktemp -d "$(dirname "$target")/.rootfs.XXXXXXXX")"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

debootstrap --arch=amd64 --variant=minbase \
  --include=bash,coreutils,gcc,libc6-dev,libtirpc-dev,make,rpcsvc-proto,iproute2,nfs-common,nfs-kernel-server,python3,rpcbind,util-linux,procps \
  noble "$work/root" http://archive.ubuntu.com/ubuntu/

mkdir -p "$work/root/usr/local/sbin"
install -m 0755 "$(dirname "$0")/guest-init.sh" "$work/root/usr/local/sbin/hivemind-guest-init"
install -m 0755 "$(dirname "$0")/guest-job.py" "$work/root/usr/local/sbin/hivemind-guest-job.py"
mkdir -p "$work/root/dev" "$work/root/proc" "$work/root/sys" "$work/root/mnt/job" "$work/root/mnt/nfs" "$work/root/srv/export"
rm -f "$work/root/etc/hosts" "$work/root/etc/resolv.conf"
printf '127.0.0.1 localhost\n10.77.0.1 nfs-server\n10.77.0.2 nfs-client\n' > "$work/root/etc/hosts"
printf 'nameserver 127.0.0.1\n' > "$work/root/etc/resolv.conf"

truncate -s 2G "$work/rootfs.raw"
mkfs.ext4 -q -F -d "$work/root" "$work/rootfs.raw"
chmod 0644 "$work/rootfs.raw"
mv "$work/rootfs.raw" "$target"
echo "created $target"
