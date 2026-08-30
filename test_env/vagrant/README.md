# Recce test-env — Vagrant plane (Phase 9c)

The recce test environment's Docker plane (`test_env/docker-compose.yml`) covers
every protocol that reproduces cleanly inside a container. This directory adds
the three services that genuinely need a full OS:

| VM | Address | Provides | Backing |
|---|---|---|---|
| `ad-dc` | 172.20.1.10 | Windows Server 2022 AD DC — Kerberos KDC, DPAPI, WinRM, real SMB2 signing negotiation | `gusztavvargadr/windows-server-2022-standard` (free public box) |
| `bmc` | 172.20.1.20 | IPMI 2.0 BMC — Get Channel Auth Capabilities + RAKP1/RAKP2 | Ubuntu 22.04 + `virtualbmc==2.2.2` + libvirt fake domain |
| `kernelnet` | 172.20.1.30 | LIO iSCSI (3260) + NFSv4 (2049) + NBD (10809) | Ubuntu 22.04 + `targetcli-fb` + `nfs-kernel-server` + `nbd-server` |

The Vagrant private network sits on **172.20.1.0/24**, deliberately separate
from the Docker plane's **172.20.0.0/24** — no accidental routing between the
two. The recce host reaches both because it's on the LAN, not either subnet.

## Bring up

Boxes are on the public Vagrant Cloud (no paid subscription):

    cd test_env/vagrant
    vagrant up               # all three
    vagrant up ad-dc         # just the DC (~10-15 min first run — dcpromo)
    vagrant up bmc           # just IPMI (~2 min)
    vagrant up kernelnet     # just iSCSI/NFS/NBD (~1 min)

Full plane footprint: **~7 GB RAM, ~60 GB disk** when running.

## Providers

The Vagrantfile ships provider blocks for **virtualbox** and **libvirt**. Which
one Vagrant picks depends on what's installed; VirtualBox is the more common
default on macOS/Windows dev boxes, libvirt on Linux with kvm.

    vagrant up --provider=virtualbox    # explicit
    vagrant up --provider=libvirt       # explicit

## Test accounts (AD DC)

Seeded by `provision-ad.ps1`. Every credential documented here matches what
recce's tests + docs expect:

| Account | Password | Role |
|---|---|---|
| Administrator | `Passw0rd!` | Domain Admin |
| svc_backup | `Summer2024!` | SPN `MSSQLSvc/dc01.corp.local:1433` — **kerberoastable** |
| svc_sql | `Autumn2024!` | SPN `HTTP/dc01.corp.local` — **kerberoastable** |
| alice | `alice1234` | Domain Users |
| bob | `bob1234` | Domain Users |
| legacy.app | `LegacyBadPass1` | `DONT_REQ_PREAUTH` — **AS-REP roastable** |

Domain: **CORP.LOCAL** (NetBIOS **CORP**). DSRM: `P@ssw0rd_DSRM`.

## Test accounts (BMC)

| Combo | Notes |
|---|---|
| `ADMIN` / `ADMIN` | virtualBMC default — recce ipmi should flag this |
| `root` / `calvin` | seeded because recce's default-cred sweep tests iDRAC defaults |

## iSCSI / NFS / NBD targets (kernelnet)

- **iSCSI**: portal `172.20.1.30:3260`, IQN `iqn.2026-08.test.recce:lun0`, one 128 MB file-backed LUN, `demo_mode_write_protect=0` (anonymous mount OK — the classic exposure recce iscsi probes).
- **NFSv4**: exports `/srv/nfs` to `172.20.1.0/24` with `no_root_squash`. Contains a single `README` file.
- **NBD**: export name `recce`, 32 MB backing file, read/write.

## Env-gate markers

`tests/conftest.py` recognises three VM canaries:

    @pytest.mark.needs_vagrant("ad-dc")       # canary 172.20.1.10:445
    @pytest.mark.needs_vagrant("bmc")         # canary 172.20.1.20:623 (best-effort — UDP)
    @pytest.mark.needs_vagrant("kernelnet")   # canary 172.20.1.30:3260

Tests using these markers **SKIP cleanly** when the VM isn't up — CI runs that
haven't provisioned Vagrant still pass the fast lane.

## Provisioning is idempotent

Every provision script skips work it's already done on a previous run, so
`vagrant provision` after a change is fast. `vagrant destroy && vagrant up` is
the "rebuild from scratch" path — ~15 min for `ad-dc`, ~2-3 min for each Linux VM.

## Teardown

    vagrant halt              # keeps state, faster next boot
    vagrant destroy -f        # nukes disks — first-boot cost again on `up`

Delete the cached boxes to reclaim ~4 GB:

    vagrant box remove gusztavvargadr/windows-server-2022-standard
    vagrant box remove generic/ubuntu2204
