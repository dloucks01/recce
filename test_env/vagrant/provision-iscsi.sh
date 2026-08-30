#!/usr/bin/env bash
# Recce test-env kernel-privileged Ubuntu provisioning
#
# Runs on the Vagrant Ubuntu 22.04 box. Sets up the services that need
# kernel modules or configfs and therefore can't live in a plain Docker
# container:
#
#   iSCSI (LIO/targetcli) — 172.20.1.30:3260  (IQN iqn.2026-08.test.recce:lun0)
#   NFSv4 export           — 172.20.1.30:2049 (/srv/nfs, rw, no_root_squash)
#   NBD real server        — 172.20.1.30:10809 (export "recce", 32 MB backing file)
#
# Idempotent — subsequent `vagrant provision` skips already-configured pieces.

set -euo pipefail

# ── 1. Base packages ────────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q \
    targetcli-fb open-iscsi \
    nfs-kernel-server nfs-common \
    nbd-server \
    xfsprogs curl

# ── 2. iSCSI: LIO target with one file-backed LUN ──────────────────────
BACKING=/var/lib/iscsi_disks
mkdir -p "${BACKING}"
if [ ! -f "${BACKING}/lun0.img" ]; then
    echo "[+] creating 128 MB iSCSI backing file"
    truncate -s 128M "${BACKING}/lun0.img"
fi

IQN="iqn.2026-08.test.recce:lun0"

# Idempotent build via targetcli:  if the target already exists we skip.
if ! targetcli /iscsi ls 2>/dev/null | grep -q "${IQN}"; then
    echo "[+] configuring LIO iSCSI target ${IQN}"
    targetcli <<TCLI
backstores/fileio create name=lun0 file_or_dev=${BACKING}/lun0.img size=128M
iscsi/ create wwn=${IQN}
iscsi/${IQN}/tpg1/luns create /backstores/fileio/lun0
iscsi/${IQN}/tpg1 set attribute authentication=0 demo_mode_write_protect=0 generate_node_acls=1
iscsi/${IQN}/tpg1/portals delete 0.0.0.0 3260 || true
iscsi/${IQN}/tpg1/portals create 172.20.1.30 3260
saveconfig
TCLI
fi

systemctl enable --now rtslib-fb-targetctl.service || true

# ── 3. NFSv4 export ────────────────────────────────────────────────────
mkdir -p /srv/nfs
chmod 0777 /srv/nfs
echo "test-file" > /srv/nfs/README

if ! grep -q "^/srv/nfs " /etc/exports 2>/dev/null; then
    echo "[+] adding NFS export /srv/nfs"
    echo "/srv/nfs 172.20.1.0/24(rw,sync,no_subtree_check,no_root_squash)" >> /etc/exports
fi
exportfs -ra
systemctl enable --now nfs-kernel-server

# ── 4. NBD: one 32 MB export named "recce" ─────────────────────────────
NBD_BACKING=/var/lib/nbd-disk.img
if [ ! -f "${NBD_BACKING}" ]; then
    truncate -s 32M "${NBD_BACKING}"
fi

if [ ! -f /etc/nbd-server/config ] || ! grep -q "\[recce\]" /etc/nbd-server/config; then
    echo "[+] configuring NBD export 'recce' at ${NBD_BACKING}"
    mkdir -p /etc/nbd-server
    cat >/etc/nbd-server/config <<CFG
[generic]
    user = nbd
    group = nbd
    includedir = /etc/nbd-server/conf.d

[recce]
    exportname = ${NBD_BACKING}
    readonly = false
CFG
fi

systemctl enable --now nbd-server

# ── 5. Smoke tests ────────────────────────────────────────────────────
echo "[+] smoke: iSCSI"
ss -tln | grep ":3260 " || echo "  ! 3260 not listening"
echo "[+] smoke: NFS"
showmount -e 127.0.0.1 || true
echo "[+] smoke: NBD"
ss -tln | grep ":10809 " || echo "  ! 10809 not listening"

echo "[+] Recce test kernelnet VM ready at 172.20.1.30 (iSCSI/NFS/NBD)"
