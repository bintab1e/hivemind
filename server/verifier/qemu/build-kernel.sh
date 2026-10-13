#!/usr/bin/env bash
set -euo pipefail

if (( $# < 2 || $# > 3 )); then
  echo "usage: $0 /absolute/kernel/source /absolute/build/directory [jobs]" >&2
  exit 2
fi
source_dir="$(realpath "$1")"
build_dir="$2"
jobs="${3:-2}"
[[ -f "$source_dir/Makefile" && "$build_dir" = /* && "$jobs" =~ ^[1-9][0-9]*$ ]] || {
  echo "invalid kernel source, absolute build directory, or job count" >&2
  exit 2
}
commit="$(git -C "$source_dir" rev-parse --verify HEAD^{commit})"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || {
  echo "kernel source must be a clean Git checkout for commit binding" >&2
  exit 2
}
mkdir -p "$build_dir"
build_dir="$(realpath "$build_dir")"
[[ "$build_dir" != "$source_dir" && "$build_dir" != "$source_dir/"* ]] || {
  echo "out-of-tree build directory required" >&2
  exit 2
}

make -C "$source_dir" O="$build_dir" x86_64_defconfig
config="$build_dir/.config"
"$source_dir/scripts/config" --file "$config" \
  -e DEBUG_KERNEL -d DEBUG_INFO_NONE -e DEBUG_INFO_DWARF4 -e KALLSYMS -e KALLSYMS_ALL \
  -e DEVTMPFS -e DEVTMPFS_MOUNT -e VIRTIO -e VIRTIO_PCI -e VIRTIO_BLK -e VIRTIO_NET \
  -e EXT4_FS -e INET -e SUNRPC -e LOCKD -e NFS_FS -e NFS_V3 -e NFS_V4 -e NFS_V4_1 -e NFS_V4_2 \
  -e NFSD -e NFSD_V3 -e NFSD_V4 -e NFSD_PNFS -e KASAN -e KASAN_GENERIC
make -C "$source_dir" O="$build_dir" olddefconfig
for setting in CONFIG_DEVTMPFS=y CONFIG_VIRTIO_BLK=y CONFIG_VIRTIO_NET=y CONFIG_EXT4_FS=y CONFIG_NFSD=y CONFIG_NFS_FS=y CONFIG_KASAN=y CONFIG_DEBUG_INFO=y CONFIG_DEBUG_INFO_DWARF4=y CONFIG_KALLSYMS=y; do
  grep -qx "$setting" "$config" || { echo "kernel config did not enable $setting" >&2; exit 1; }
done
make -C "$source_dir" O="$build_dir" -j "$jobs" bzImage vmlinux
image="$build_dir/arch/x86/boot/bzImage"
vmlinux="$build_dir/vmlinux"
readelf --sections --wide "$vmlinux" | grep -q '\.debug_info' || {
  echo "built vmlinux has no DWARF debug information" >&2
  exit 1
}
[[ "$(git -C "$source_dir" rev-parse --verify HEAD^{commit})" = "$commit" && -z "$(git -C "$source_dir" status --porcelain)" ]] || {
  echo "kernel source changed during the build" >&2
  exit 1
}
digest="$(sha256sum "$image" | cut -d' ' -f1)"
vmlinux_digest="$(sha256sum "$vmlinux" | cut -d' ' -f1)"
printf '{"sourceCommit":"%s","kernelSha256":"%s","vmlinuxSha256":"%s"}\n' "$commit" "$digest" "$vmlinux_digest" > "$build_dir/kernel-info.json"
echo "kernel image: $build_dir/arch/x86/boot/bzImage"
echo "symbol image: $vmlinux"
