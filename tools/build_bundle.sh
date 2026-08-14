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
#   ./tools/build_bundle.sh                 # build for the current version
#   RECCE_WITH_MASSCAN=0 ./tools/build_bundle.sh   # skip masscan
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

# --- 1. throwaway build venv with recce + its deps + pyinstaller ----------------
echo "[*] Creating build venv + installing recce (+ deps) + PyInstaller ..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet '.[bundle]'  # recce + the bundled libraries (impacket/ldap3/openpyxl)
"$VENV/bin/pip" install --quiet pyinstaller

# --- 2. freeze the recce app (onedir) -------------------------------------------
echo "[*] Freezing the recce app with PyInstaller ..."
cat > "$BUILD/entry.py" <<'PY'
from recce.cli import main
if __name__ == "__main__":
    main()
PY
# --collect-all for the bundled libs: recce imports them conditionally (find_spec),
# which PyInstaller's static analysis would otherwise miss.
"$VENV/bin/pyinstaller" --onedir --name recce --noconfirm \
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

echo "[*] Bundling external tools ..."
# nmap: /usr/bin/nmap is a privilege wrapper; the real ELF is /usr/lib/nmap/nmap.
NMAP_BIN="/usr/lib/nmap/nmap"; [ -x "$NMAP_BIN" ] || NMAP_BIN="$(command -v nmap || true)"
bundle_tool nmap "$NMAP_BIN" /usr/share/nmap NMAPDIR
[ "${RECCE_WITH_MASSCAN:-1}" = "1" ] && bundle_tool masscan "$(readlink -f "$(command -v masscan || true)")"

# --- 4. launcher ----------------------------------------------------------------
cat > "$OUT/recce" <<'SH'
#!/bin/sh
# recce airgap launcher: run the bundled app with the bundled tools on PATH.
DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
export PATH="$DIR/tools/bin:$PATH"
exec "$DIR/app/recce" "$@"
SH
chmod +x "$OUT/recce"

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
echo "[+] Done: dist/$NAME/  (run: dist/$NAME/recce doctor)"
echo "    tarball: dist/$NAME.tar.gz  ($(du -sh "$HERE/dist/$NAME.tar.gz" | cut -f1))"
echo "    total unpacked: $(du -sh "$OUT" | cut -f1)"
