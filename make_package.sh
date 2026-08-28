#!/usr/bin/env bash
# make_package.sh - build the airgapped "burn package": a self-contained bundle of
# recce you copy to a Kali box (or burn to a disk) and run offline. No network, no
# pip install needed at runtime - recce is stdlib-only.
#
# Produces  dist/recce-<version>.tar.gz  and  dist/recce-<version>.zip  (if `zip`
# is present), each containing a single top-level recce-<version>/ directory, plus
# SHA256SUMS for burn/transfer verification.
#
# Usage:  ./make_package.sh                  # build tar.gz (+ zip if available)
#         ./make_package.sh --verify         # also run the test suite before packaging
#         ./make_package.sh --refresh-intel  # refresh KEV/EPSS snapshots from the
#                                            # upstream feeds first (needs internet;
#                                            # falls back to the committed snapshots)
set -eu

REFRESH_INTEL=0
VERIFY=0
for _arg in "$@"; do
  case "$_arg" in
    --refresh-intel) REFRESH_INTEL=1 ;;
    --verify) VERIFY=1 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

VER="$(sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' recce/__init__.py)"
[ -n "$VER" ] || { echo "could not read recce/__init__.py __version__"; exit 1; }
NAME="recce-$VER"
DIST="$HERE/dist"
STAGE="$DIST/$NAME"

if [ "$REFRESH_INTEL" = 1 ]; then
  echo "[*] Refreshing KEV/EPSS snapshots from upstream feeds ..."
  python3 tools/refresh_intel.py \
    || echo "[!] intel refresh failed (network?) - keeping the committed snapshots"
fi

if [ "$VERIFY" = 1 ]; then
  echo "[*] Running test suite before packaging ..."
  python3 -m unittest discover -s tests -p "test_*.py" >/dev/null
  echo "[+] tests passed"
  # Use ruff, matching the CI lint gate. A bare `pyflakes recce` reports ~683
  # findings here - the star-import warnings the cli/ and services/web/ packages
  # produce by design - so it printed a wall of non-issues and told the operator
  # to "review above". Ruff reads the suppressions in pyproject.toml [tool.ruff]
  # and is clean, so anything it prints is a genuine finding.
  if command -v ruff >/dev/null 2>&1; then
    echo "[*] Running ruff lint ..."
    ruff check recce || echo "[!] ruff reported issues (non-fatal here; CI gates on this) - review above"
  else
    echo "[!] ruff not installed - skipping lint (pip install ruff)"
  fi
fi

# Build the web workbench UI into recce/webui/static so the burn package SHIPS it.
# (build_bundle.sh does this for the airgap bundle; the source burn package needs it
# too, else `recce serve` has no UI.) node_modules are local, so this works offline.
if [ -d recce/webui/frontend ] && command -v npm >/dev/null 2>&1; then
  echo "[*] Building the web workbench UI ..."
  ( cd recce/webui/frontend && npm install --silent && npm run build --silent ) \
    && echo "[+] web UI built into recce/webui/static" \
    || echo "[!] web UI build failed - the burn package will ship without the workbench UI"
elif [ ! -f recce/webui/static/index.html ]; then
  echo "[!] npm/frontend not found and no prebuilt UI - burn package ships without the workbench UI"
fi

echo "[*] Staging $NAME ..."
rm -rf "$STAGE"
mkdir -p "$STAGE"

# What ships in the bundle: everything an operator needs to RUN recce offline.
# The test suite and the docker lab (test_env/) are development artifacts - they
# stay in the repo, where CI runs them, and are not carried into the field.
# `--verify` still runs the suite from the source tree before staging.
INCLUDE="recce bin docs README.md QUICKSTART.md CHEATSHEET.html TROUBLESHOOTING.md \
         INTEGRATION.md CHANGELOG.md LICENSE pyproject.toml SYSTEM-REQUIREMENTS.txt \
         make_package.sh tools"
for item in $INCLUDE; do
  [ -e "$item" ] && cp -r "$item" "$STAGE/" || echo "  (skip missing: $item)"
done

# Scrub anything that shouldn't ship (caches, build/scan output, VCS, client data).
find "$STAGE" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -type d -name '*.egg-info' -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" \( -name '*.pyc' -o -name '*.sqlite' -o -name '*.xlsx' -o -name '*.rdb' \
     -o -name '.DS_Store' \) -delete 2>/dev/null || true
rm -rf "$STAGE/engagement" "$STAGE/demo_engagement" "$STAGE/dist" "$STAGE/.git" 2>/dev/null || true
# The frontend SOURCE + node_modules are build inputs, not runtime - the burn package
# ships the built SPA (recce/webui/static) only. Dropping node_modules also avoids
# bloating the archive by hundreds of MB.
rm -rf "$STAGE/recce/webui/frontend" 2>/dev/null || true
# Ensure the shell tools stay executable after copy.
chmod +x "$STAGE/bin/recce" "$STAGE/recce/local/"*.sh \
         "$STAGE/recce/scripts/"*.sh "$STAGE/recce/scripts/services/"*.sh \
         "$STAGE/make_package.sh" "$STAGE/tools/"*.sh 2>/dev/null || true

echo "[*] Archiving ..."
cd "$DIST"
rm -f "$NAME.tar.gz" "$NAME.zip" SHA256SUMS
tar -czf "$NAME.tar.gz" "$NAME"
if command -v zip >/dev/null 2>&1; then
  zip -qr "$NAME.zip" "$NAME"
else
  echo "  (zip not installed - tar.gz only)"
fi

# Checksums for verifying the transfer/burn.
# The unquoted $( ... ) is deliberate: when the zip is absent the substitution
# must expand to NO argument at all. Quoting it would pass an empty string,
# which sha256sum reports as a missing file. $NAME has no spaces (recce-<ver>).
if command -v sha256sum >/dev/null 2>&1; then
  # shellcheck disable=SC2046  # intentional: empty expansion must vanish
  sha256sum "$NAME".tar.gz $( [ -f "$NAME.zip" ] && echo "$NAME.zip" ) > SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
  # shellcheck disable=SC2046  # intentional: empty expansion must vanish
  shasum -a 256 "$NAME".tar.gz $( [ -f "$NAME.zip" ] && echo "$NAME.zip" ) > SHA256SUMS
fi
rm -rf "$STAGE"

echo
echo "[+] Burn package built in dist/:"
ls -lh "$DIST"/"$NAME".* 2>/dev/null | awk '{print "    "$9"  ("$5")"}'
[ -f "$DIST/SHA256SUMS" ] && { echo "    SHA256SUMS:"; sed 's/^/      /' "$DIST/SHA256SUMS"; }
echo
echo "    On the target:  tar xzf $NAME.tar.gz && cd $NAME && ./bin/recce doctor"
