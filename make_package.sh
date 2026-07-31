#!/usr/bin/env bash
# make_package.sh - build the airgapped "burn package": a self-contained bundle of
# recce you copy to a Kali box (or burn to a disk) and run offline. No network, no
# pip install needed at runtime - recce is stdlib-only.
#
# Produces  dist/recce-<version>.tar.gz  and  dist/recce-<version>.zip  (if `zip`
# is present), each containing a single top-level recce-<version>/ directory, plus
# SHA256SUMS for burn/transfer verification.
#
# Usage:  ./make_package.sh            # build tar.gz (+ zip if available)
#         ./make_package.sh --verify   # also run the test suite before packaging
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

VER="$(sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' recce/__init__.py)"
[ -n "$VER" ] || { echo "could not read recce/__init__.py __version__"; exit 1; }
NAME="recce-$VER"
DIST="$HERE/dist"
STAGE="$DIST/$NAME"

if [ "${1:-}" = "--verify" ]; then
  echo "[*] Running test suite before packaging ..."
  python3 -m unittest discover -s tests -p "test_*.py" >/dev/null
  python3 -m pyflakes recce >/dev/null 2>&1 || true
  echo "[+] tests passed"
fi

echo "[*] Staging $NAME ..."
rm -rf "$STAGE"
mkdir -p "$STAGE"

# What ships in the bundle. Everything needed to run + verify offline; nothing
# client- or scan-specific.
INCLUDE="recce bin tests README.md QUICKSTART.md CHEATSHEET.html TROUBLESHOOTING.md \
         INTEGRATION.md CHANGELOG.md LICENSE pyproject.toml requirements.txt make_package.sh"
for item in $INCLUDE; do
  [ -e "$item" ] && cp -r "$item" "$STAGE/" || echo "  (skip missing: $item)"
done

# Scrub anything that shouldn't ship (caches, build/scan output, VCS, client data).
find "$STAGE" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -type d -name '*.egg-info' -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" \( -name '*.pyc' -o -name '*.sqlite' -o -name '*.xlsx' -o -name '*.rdb' \
     -o -name '.DS_Store' \) -delete 2>/dev/null || true
rm -rf "$STAGE/engagement" "$STAGE/demo_engagement" "$STAGE/dist" "$STAGE/.git" 2>/dev/null || true
# Ensure the shell tools stay executable after copy.
chmod +x "$STAGE/bin/recce" "$STAGE/recce/local/"*.sh \
         "$STAGE/recce/scripts/"*.sh "$STAGE/recce/scripts/services/"*.sh \
         "$STAGE/make_package.sh" 2>/dev/null || true

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
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$NAME".tar.gz $( [ -f "$NAME.zip" ] && echo "$NAME.zip" ) > SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$NAME".tar.gz $( [ -f "$NAME.zip" ] && echo "$NAME.zip" ) > SHA256SUMS
fi
rm -rf "$STAGE"

echo
echo "[+] Burn package built in dist/:"
ls -lh "$DIST"/"$NAME".* 2>/dev/null | awk '{print "    "$9"  ("$5")"}'
[ -f "$DIST/SHA256SUMS" ] && { echo "    SHA256SUMS:"; sed 's/^/      /' "$DIST/SHA256SUMS"; }
echo
echo "    On the target:  tar xzf $NAME.tar.gz && cd $NAME && ./bin/recce doctor"
