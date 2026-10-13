#!/bin/sh
set -eu
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
for device in /dev/ttyS0 /dev/console /dev/kmsg; do
  if [ -e "$device" ]; then chmod 0600 "$device"; fi
done
mkdir -p /dev/pts /run /tmp /mnt/job /mnt/nfs /srv/export /proc/fs/nfsd
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
chmod 1777 /tmp
mount -t ext4 -o ro /dev/vdb /mnt/job
ip link set lo up
ip link set eth0 up

case " $(cat /proc/cmdline) " in
  *" hivemind.role=server "*)
    ip addr add 10.77.0.1/30 dev eth0
    chmod 0777 /srv/export
    mount -t nfsd nfsd /proc/fs/nfsd
    printf '%s\n' '/srv/export 10.77.0.2(rw,sync,no_subtree_check,no_root_squash,fsid=0)' > /etc/exports
    mkdir -p /run/rpcbind
    rpcbind -w
    exportfs -ra
    rpc.mountd -F >/dev/console 2>&1 &
    rpc.nfsd 4
    echo HV_SERVER_READY
    ;;
  *" hivemind.role=client "*)
    ip addr add 10.77.0.2/30 dev eth0
    if python3 /usr/local/sbin/hivemind-guest-job.py client; then
      echo HV_GUEST_DONE
    else
      echo HV_GUEST_FAILED
    fi
    ;;
  *)
    echo HV_GUEST_ERROR:ROLE
    ;;
esac

while :; do sleep 3600; done
