#!/usr/bin/env bash
# build_bundle.sh - build the self-contained airgap bundle.
#
# Produces a single folder you copy to an offline box and run with NOTHING installed
# (no Python, no pip, no nmap). It contains:
#   - the recce app frozen with PyInstaller (Python runtime + all deps baked in)
#   - the external C tools (nmap, masscan) with their shared libs + data
#   - a launcher that wires the bundled tools onto PATH and runs the app
#
# Run this ONLINE (it pip-installs recce + its deps + PyInstaller into a throwaway
# venv). The resulting folder is what goes on the USB stick. Build on the same
# OS/arch as the target (Kali x86-64 -> Kali x86-64).
#
#   ./tools/build_bundle.sh                 # build the lean self-contained bundle
#
# Bundled by default: the frozen recce app (Python + all deps), nmap, masscan,
# and ldapsearch. Opt in to the heavy extras (each logged; off by default):
#   RECCE_WITH_SEARCHSPLOIT=1   bundle searchsploit + the ~292MB offline exploit-db
#   RECCE_WITH_SMBCLIENT=1      bundle smbclient (pulls ~120 Samba shared libs)
#   RECCE_WITH_MASSCAN=0        skip masscan
#   RECCE_WITH_LDAPSEARCH=0     skip ldapsearch
# netexec (credenum) is NOT frozen in - install it on the target if you need it
# (`pipx install netexec`); recce degrades cleanly and logs when it is absent.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

VER="$(sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' recce/__init__.py)"
[ -n "$VER" ] || { echo "could not read recce/__init__.py __version__"; exit 1; }
NAME="recce-airgap-$VER"
OUT="$HERE/dist/$NAME"
BUILD="$HERE/dist/.build"
VENV="$BUILD/venv"

echo "[*] Building $NAME (airgap bundle)"
rm -rf "$OUT" "$BUILD"
mkdir -p "$OUT/app" "$OUT/tools/bin" "$OUT/tools/libexec" "$BUILD"

# --- 0. build the React frontend into recce/webui/static (needs Node; online build) ---
if [ -d recce/webui/frontend ] && command -v npm >/dev/null 2>&1; then
  echo "[*] Building the React frontend ..."
  ( cd recce/webui/frontend && npm install --silent && npm run build --silent )
else
  echo "[!] Node/npm or the frontend not found - the web workbench UI won't be bundled"
fi

# --- 1. build venv with recce + its deps + pyinstaller --------------------------
# --system-site-packages so an OFFLINE build (no PyPI reachable) can reuse deps that
# are already installed on the box (impacket/ldap3/openpyxl/fastapi/uvicorn/pyinstaller)
# instead of failing at pip. Online, the '.[bundle]' install still pulls anything missing.
echo "[*] Creating build venv + installing recce (+ deps) + PyInstaller ..."
python3 -m venv --system-site-packages "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip 2>/dev/null || true
if "$VENV/bin/pip" install --quiet '.[bundle]' pyinstaller 2>/dev/null; then
  echo "[+] installed recce + deps from PyPI"
else
  echo "[!] PyPI unreachable - building OFFLINE from the deps already on this box"
fi
# Verify the deps needed to freeze are importable (from the venv or system-site).
"$VENV/bin/python" -c "import PyInstaller, fastapi, uvicorn" \
  || { echo "[x] missing build deps (need PyInstaller + fastapi + uvicorn). Install them and retry."; exit 1; }

# --- 2. freeze the recce app (onedir) -------------------------------------------
echo "[*] Freezing the recce app with PyInstaller ..."
cat > "$BUILD/entry.py" <<'PY'
from recce.cli import main
if __name__ == "__main__":
    main()
PY
# --collect-all for the bundled libs: recce imports them conditionally (find_spec),
# which PyInstaller's static analysis would otherwise miss.
# --paths "$HERE": find the recce package in the repo even when it wasn't pip-installed
# (the offline path). python -m PyInstaller works whether pyinstaller is in the venv or
# the system site-packages the venv can see.
"$VENV/bin/python" -m PyInstaller --onedir --name recce --noconfirm \
  --paths "$HERE" \
  --collect-submodules recce --collect-data recce \
  --collect-all impacket --collect-all ldap3 --collect-all openpyxl \
  --collect-all fastapi --collect-all uvicorn \
  --distpath "$BUILD/pyi-dist" --workpath "$BUILD/pyi-work" --specpath "$BUILD" \
  "$BUILD/entry.py" >/dev/null 2>&1
cp -a "$BUILD/pyi-dist/recce/." "$OUT/app/"

# --- 3. bundle a C tool: real ELF + its shared libs (+ optional data dir) --------
# bundle_tool <name> <real-binary> [<data-dir> <DATA_ENV_VAR>]
bundle_tool() {
  local name="$1" bin="$2" data="${3:-}" datavar="${4:-}"
  [ -x "$bin" ] || { echo "[!] $name: $bin not found - skipping"; return; }
  local lx="$OUT/tools/libexec/$name"
  mkdir -p "$lx/lib"
  cp -L "$bin" "$lx/$name.bin"
  # copy every shared lib the binary resolves (same-distro build host)
  ldd "$bin" 2>/dev/null | awk '/=>/{print $3} /ld-linux/{print $1}' \
    | grep -E '^/' | sort -u | while read -r so; do cp -Lu "$so" "$lx/lib/" 2>/dev/null || true; done
  [ -n "$data" ] && cp -a "$data" "$lx/data"
  # wrapper on tools/bin that points the loader + data dir at the bundle
  {
    echo '#!/bin/sh'
    echo 'D="$(cd "$(dirname "$(readlink -f "$0")")/../libexec/'"$name"'" && pwd)"'
    echo 'export LD_LIBRARY_PATH="$D/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"'
    [ -n "$datavar" ] && echo 'export '"$datavar"'="$D/data"'
    echo 'exec "$D/'"$name"'.bin" "$@"'
  } > "$OUT/tools/bin/$name"
  chmod +x "$OUT/tools/bin/$name"
  echo "[+] bundled $name ($(du -sh "$lx" | cut -f1))"
}

# bundle_searchsploit: ship the searchsploit script + the offline exploit-db as data,
# with a wrapper that points searchsploit at the bundled DB via a bundle-local rc.
bundle_searchsploit() {
  local ss db lx
  ss="$(command -v searchsploit || true)"
  db=""; for d in /usr/share/exploitdb /opt/exploitdb; do [ -d "$d" ] && { db="$d"; break; }; done
  [ -x "$ss" ] && [ -n "$db" ] || { echo "[!] searchsploit/exploit-db not found - skipping"; return; }
  lx="$OUT/tools/libexec/searchsploit"
  mkdir -p "$lx"
  cp -L "$ss" "$lx/searchsploit.bin"
  chmod +x "$lx/searchsploit.bin"
  cp -a "$db" "$lx/exploitdb"
  # rc template resolved to the bundle path at runtime by the wrapper. Current
  # searchsploit sources arrays (files_array/path_array/name_array), NOT DEFAULT_PATH.
  {
    printf 'files_array+=("files_exploits.csv")\npath_array+=("%s/exploitdb")\nname_array+=("Exploit")\n' '$D'
    printf 'files_array+=("files_shellcodes.csv")\npath_array+=("%s/exploitdb")\nname_array+=("Shellcode")\n' '$D'
  } > "$lx/searchsploit_rc.tmpl"
  {
    echo '#!/bin/sh'
    echo 'D="$(cd "$(dirname "$(readlink -f "$0")")/../libexec/searchsploit" && pwd)"'
    echo 'H="$(mktemp -d)"; trap '"'"'rm -rf "$H"'"'"' EXIT'
    echo 'sed "s#[$]D#$D#g" "$D/searchsploit_rc.tmpl" > "$H/.searchsploit_rc"'
    # searchsploit is a bash script (bash syntax) - run it with bash, not sh/dash.
    echo 'HOME="$H" exec bash "$D/searchsploit.bin" "$@"'
  } > "$OUT/tools/bin/searchsploit"
  chmod +x "$OUT/tools/bin/searchsploit"
  echo "[+] bundled searchsploit + exploit-db ($(du -sh "$lx" | cut -f1))"
}

echo "[*] Bundling external tools ..."
# nmap: /usr/bin/nmap is a privilege wrapper; the real ELF is /usr/lib/nmap/nmap.
NMAP_BIN="/usr/lib/nmap/nmap"; [ -x "$NMAP_BIN" ] || NMAP_BIN="$(command -v nmap || true)"
bundle_tool nmap "$NMAP_BIN" /usr/share/nmap NMAPDIR
[ "${RECCE_WITH_MASSCAN:-1}" = "1" ] && bundle_tool masscan "$(readlink -f "$(command -v masscan || true)")"
# ldapsearch (OpenLDAP client): tiny ELF; hardens credentialed LDAP beyond the
# baked-in ldap3 fallback. On by default when present.
[ "${RECCE_WITH_LDAPSEARCH:-1}" = "1" ] && bundle_tool ldapsearch "$(readlink -f "$(command -v ldapsearch || true)")"
# smbclient (Samba client): OPT-IN - pulls ~120 shared libs, so it is off by default.
[ "${RECCE_WITH_SMBCLIENT:-0}" = "1" ] && bundle_tool smbclient "$(readlink -f "$(command -v smbclient || true)")"
# searchsploit + offline exploit-db (~292MB): OPT-IN.
[ "${RECCE_WITH_SEARCHSPLOIT:-0}" = "1" ] && bundle_searchsploit

# --- 4. launcher ----------------------------------------------------------------
cat > "$OUT/recce" <<'SH'
#!/bin/sh
# recce airgap launcher: run the bundled app with the bundled tools on PATH.
DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
export PATH="$DIR/tools/bin:$PATH"
exec "$DIR/app/recce" "$@"
SH
chmod +x "$OUT/recce"

# --- 4b. MANIFEST (ships inside the bundle) -------------------------------------
echo "[*] Writing MANIFEST ..."
{
  echo "recce airgap bundle - $NAME"
  echo "built: $(date -u '+%Y-%m-%d %H:%M UTC') on $(uname -srm)"
  echo
  echo "RUN (nothing to install - no Python, no pip, no nmap):"
  echo "  tar xzf $NAME.tar.gz && cd $NAME && ./recce doctor"
  echo "  ./recce enum <targets> -o eng     # then vulns / sweep / report (see QUICKSTART)"
  echo
  echo "SELF-CONTAINED - baked into app/ (PyInstaller):"
  echo "  - Python runtime + the recce app"
  echo "  - Python deps: impacket, ldap3, openpyxl, fastapi, uvicorn"
  echo "    (AD/Kerberos/SMB, the web workbench, richer xlsx; stdlib fallback otherwise)"
  echo "  - offline intel snapshots: version->CVE/CWE DB, CISA KEV, EPSS"
  echo
  echo "BUNDLED EXTERNAL TOOLS (tools/bin, on PATH via the launcher):"
  for t in "$OUT"/tools/bin/*; do [ -e "$t" ] && echo "  - $(basename "$t")"; done
  echo
  echo "NOT bundled (recce logs + degrades cleanly; add on the target if you need it):"
  echo "  - netexec / nxc   credentialed SMB/AD spray (credenum)   ->  pipx install netexec"
  [ -e "$OUT/tools/bin/searchsploit" ] || echo "  - searchsploit    offline exploit mapping   ->  rebuild with RECCE_WITH_SEARCHSPLOIT=1"
  echo "  - chromium/firefox   auto web screenshots in write-ups"
  echo
  echo "Verify this transfer:  sha256sum -c $NAME.tar.gz.sha256"
} > "$OUT/MANIFEST.txt"

# --- 5. package + checksum ------------------------------------------------------
echo "[*] Packaging ..."
( cd "$HERE/dist" && tar czf "$NAME.tar.gz" "$NAME" \
  && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )

# --- 6. smoke test: run the launcher with a SCRUBBED environment -----------------
echo "[*] Smoke test (scrubbed env: no system python, only bundled tools on PATH) ..."
if env -i HOME=/tmp "$OUT/recce" doctor >/dev/null 2>&1; then
  echo "[+] launcher ran self-contained."
else
  echo "[!] smoke test returned non-zero (review 'recce doctor' output)"
fi

rm -rf "$BUILD"
echo
echo "[+] Done: dist/$NAME/   (run: dist/$NAME/recce doctor)"
echo "    tarball:  dist/$NAME.tar.gz  ($(du -sh "$HERE/dist/$NAME.tar.gz" | cut -f1))"
echo "    unpacked: $(du -sh "$OUT" | cut -f1)   -   contents listed in $NAME/MANIFEST.txt"
