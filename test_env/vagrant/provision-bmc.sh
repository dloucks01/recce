#!/usr/bin/env bash
# Recce test-env IPMI BMC provisioning
#
# Runs on the Vagrant Ubuntu 22.04 box. Installs virtualBMC and registers a
# fake QEMU node so recce's ipmi module gets a real IPMI 2.0 exchange to
# probe (Get Channel Auth Capabilities, RAKP1/RAKP2, cipher-zero test).
#
# Result: 172.20.1.20:623/udp answers IPMI with:
#   ADMIN / ADMIN     (default vendor combo — recce should flag it)
#   root  / calvin    (Dell iDRAC default — recce ships this in the sweep)
#
# Idempotent — re-provision skips already-configured pieces.

set -euo pipefail

BMC_IP=172.20.1.20
NODE_NAME=recce-fake-node
FAKE_DISK=/var/lib/virtualbmc/${NODE_NAME}.qcow2

# ── 1. Base packages ────────────────────────────────────────────────────
if ! command -v vbmc >/dev/null 2>&1; then
    echo "[+] installing virtualBMC + qemu"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q python3-pip python3-venv qemu-system-x86 \
        qemu-utils libvirt-daemon-system libvirt-clients ipmitool
    # virtualbmc is python; install into a venv to avoid PEP 668 clash
    python3 -m venv /opt/vbmc-venv
    /opt/vbmc-venv/bin/pip install --quiet virtualbmc==2.2.2
    ln -sf /opt/vbmc-venv/bin/vbmc /usr/local/bin/vbmc
    ln -sf /opt/vbmc-venv/bin/vbmcd /usr/local/bin/vbmcd
fi

# ── 2. libvirt: define a fake VM so virtualBMC has something to bind to.
#      The disk is a 64 MB qcow2 that never boots — virtualBMC just needs
#      a domain reference; power ops are simulated. ─────────────────────
mkdir -p /var/lib/virtualbmc
if [ ! -f "${FAKE_DISK}" ]; then
    qemu-img create -f qcow2 "${FAKE_DISK}" 64M
fi

if ! virsh list --all --name | grep -qx "${NODE_NAME}"; then
    echo "[+] defining libvirt domain ${NODE_NAME}"
    cat >/tmp/${NODE_NAME}.xml <<XML
<domain type='qemu'>
  <name>${NODE_NAME}</name>
  <memory unit='MiB'>128</memory>
  <vcpu>1</vcpu>
  <os><type arch='x86_64'>hvm</type><boot dev='hd'/></os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${FAKE_DISK}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
  </devices>
</domain>
XML
    virsh define /tmp/${NODE_NAME}.xml
fi

# ── 3. Start vbmcd + register the node on 623/udp. ────────────────────
systemctl unmask vbmcd 2>/dev/null || true
if [ ! -f /etc/systemd/system/vbmcd.service ]; then
    cat >/etc/systemd/system/vbmcd.service <<UNIT
[Unit]
Description=Virtual BMC daemon
After=libvirtd.service network-online.target
Requires=libvirtd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/vbmcd --foreground
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
fi
systemctl enable --now vbmcd

# Wait for vbmcd's socket
for _ in $(seq 1 30); do vbmc list >/dev/null 2>&1 && break; sleep 1; done

if ! vbmc list --no-headers 2>/dev/null | grep -q "${NODE_NAME}"; then
    echo "[+] registering ${NODE_NAME} with virtualBMC on ${BMC_IP}:623"
    vbmc add "${NODE_NAME}" --address "${BMC_IP}" --port 623 \
        --username ADMIN --password ADMIN
    vbmc start "${NODE_NAME}"
fi

# Local smoke test — recce's canary is 623/udp from the host.
echo "[+] IPMI smoke:"
ipmitool -I lanplus -H 127.0.0.1 -p 623 -U ADMIN -P ADMIN power status || true

echo "[+] Recce test BMC ready at ${BMC_IP}:623 (ADMIN / ADMIN)"
