# Packaging, transfer & airgap

Two ways to ship recce — pick based on what the target already has:

| Package | Build with | Target needs | Size |
| --- | --- | --- | --- |
| Source | `./make_package.sh` | Python 3.9+ and nmap | ~1 MB |
| Airgap bundle | `./tools/build_bundle.sh` | Nothing | ~45 MB |

Both are built once on a connected box and copied over. Build on the same OS/arch as the target.

## Source package (`make_package.sh`)

Pure-Python source plus the built web UI. Stdlib-only at runtime.

```bash
./make_package.sh                    # -> dist/recce-<version>.tar.gz + SHA256SUMS
./make_package.sh --verify           # run tests first
./make_package.sh --refresh-intel    # refresh KEV/EPSS snapshots first
```

On the target:
```bash
tar xzf recce-<version>.tar.gz && cd recce-<version> && ./bin/recce doctor
```

The web workbench (`recce serve`) needs `fastapi` + `uvicorn`, which this package does not carry — use the airgap bundle for that, or `pip install 'recce[bundle]'` on a connected box.

## Airgap bundle (`build_bundle.sh`)

A single folder that runs with nothing installed. Contains:

- recce frozen with PyInstaller (Python runtime + all deps baked in)
- nmap, masscan, ldapsearch as bundled binaries with shared libs
- a launcher that wires bundled tools onto PATH

```bash
./tools/build_bundle.sh              # -> dist/recce-airgap-<version>/ (~45 MB)
# on the target:
tar xzf recce-airgap-<version>.tar.gz && cd recce-airgap-<version> && ./recce doctor
```

**Not bundled by default** (recce degrades cleanly when absent):

| Tool | For | Add by |
| --- | --- | --- |
| searchsploit | Offline exploit mapping | `RECCE_WITH_SEARCHSPLOIT=1` (+292 MB) |
| smbclient | SMB write proofs | `RECCE_WITH_SMBCLIENT=1` (+120 MB) |
| netexec | Credentialed SMB/AD | `pipx install netexec` on target |

The build script creates its venv with `--system-site-packages`, so it can build offline from already-installed deps.

## Verifying the transfer

```bash
sha256sum -c SHA256SUMS
```
