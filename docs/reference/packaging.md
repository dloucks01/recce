# Packaging, transfer & airgap

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

recce is designed to run on a disconnected box. There are **two** ways to ship it;
pick based on what the *target* already has.

| Package | Build with | Target needs | Size | Use when |
| --- | --- | --- | --- | --- |
| **Source burn package** | `./make_package.sh` | Python 3.9+ and `nmap` installed | ~1 MB | The target is a stock Kali (Python + tools already there) |
| **Self-contained airgap bundle** | `./tools/build_bundle.sh` | **nothing** — no Python, no pip, no nmap | ~45 MB | A truly dark box, a minimal host, or you want one artifact that just runs |

Both are built **once on a connected box** and copied over; neither touches the
network at runtime. Build on the **same OS/arch** as the target (Kali x86-64 → Kali x86-64).

---

## Source burn package (`make_package.sh`)

A single `recce-<version>/` directory of the pure-Python source plus the built web
UI. recce is stdlib-only at runtime, so on a target that already has Python 3.9+
and nmap it runs as-is.

```bash
./make_package.sh              # -> dist/recce-<version>.tar.gz (+ .zip) + SHA256SUMS
./make_package.sh --verify     # run the test suite first
./make_package.sh --refresh-intel   # refresh KEV/EPSS snapshots from upstream first
```

On the target:

```bash
tar xzf recce-<version>.tar.gz && cd recce-<version> && ./bin/recce doctor
```

It stages the tool (`recce/` incl. the `local/` and `scripts/` suites), `bin/`,
the tests and the docs, scrubs caches/VCS/scan output, and writes `SHA256SUMS` for
verifying the transfer. **Caveat:** the web workbench (`recce serve`) needs
`fastapi` + `uvicorn`, which this package does **not** carry — if you need the
browser UI on an airgapped box, use the self-contained bundle below (or
`pip install 'recce[bundle]'` on a connected staging box).

---

## Self-contained airgap bundle (`build_bundle.sh`)

Produces a single folder you copy to an offline box and run **with nothing
installed**. It contains:

- the recce app **frozen with PyInstaller** — the Python runtime and every Python
  dependency (impacket, ldap3, openpyxl, fastapi, uvicorn) baked in;
- the external C tools **nmap** and **masscan** as real ELF binaries with their
  shared libraries and data;
- **ldapsearch** (a small OpenLDAP client) by default;
- a launcher that wires the bundled tools onto `PATH` and runs the app.

```bash
./tools/build_bundle.sh                     # lean self-contained bundle (~45 MB)
```

Run it **on a connected box** (it pip-installs recce + deps + PyInstaller into a
throwaway venv). The result is what goes on the USB stick:

```bash
tar xzf recce-airgap-<version>.tar.gz && cd recce-airgap-<version>
./recce doctor                              # nothing to install
./recce enum <targets> -o eng               # then vulns / sweep / report
```

Every bundle carries a **`MANIFEST.txt`** listing exactly what's inside, the run
command, and what was intentionally left out.

### What's inside vs. what isn't

**Baked in** (works with zero network): scanning (nmap/masscan), the offline
version→CVE/CWE engine, CISA KEV + EPSS snapshots, AD/Kerberos/SMB via impacket +
ldap3, the web workbench (fastapi + uvicorn), and the stdlib `.xlsx`/`.docx`
writers.

**Not bundled by default** (recce logs a note and degrades cleanly when a tool is
absent — nothing fails silently):

| Tool | For | Add it by |
| --- | --- | --- |
| `searchsploit` + exploit-db | Offline exploit mapping (Exploits sheet) | Rebuild with `RECCE_WITH_SEARCHSPLOIT=1` (adds ~292 MB), or `apt install exploitdb` on the target |
| `netexec` / `nxc` | Credentialed SMB/AD spray (`credenum`) | `pipx install netexec` on the target |
| `chromium` / `firefox` | Auto web screenshots in write-ups | Install a browser on the target, or point `RECCE_BROWSER` at one |

### Build flags

All off/on via environment variables:

```bash
RECCE_WITH_SEARCHSPLOIT=1 ./tools/build_bundle.sh   # + searchsploit + ~292 MB exploit-db
RECCE_WITH_SMBCLIENT=1     ./tools/build_bundle.sh   # + smbclient (pulls ~120 Samba libs)
RECCE_WITH_MASSCAN=0       ./tools/build_bundle.sh   # skip masscan
RECCE_WITH_LDAPSEARCH=0    ./tools/build_bundle.sh   # skip ldapsearch
```

### Offline build host

`build_bundle.sh` creates its venv with `--system-site-packages`, so when **PyPI is
unreachable** it builds from the dependencies already installed on the box
(impacket/ldap3/openpyxl/fastapi/uvicorn/pyinstaller) instead of failing at `pip`.
Install those once on your build host and you can freeze the airgap package fully
disconnected.

---

## Verifying the transfer

Both builds write a checksums file. On the target:

```bash
sha256sum -c SHA256SUMS                      # source burn package
sha256sum -c recce-airgap-<version>.tar.gz.sha256   # airgap bundle
```

## First thing to run, either way

```bash
./bin/recce doctor      # source package     (or)     ./recce doctor   # airgap bundle
```

`doctor` checks the environment, lists which capabilities are present, and runs a
real localhost self-scan — so you know the box is ready before the engagement.
