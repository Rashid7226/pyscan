#!/bin/bash
set -euo pipefail
OWNER="${PYSCAN_GITHUB_OWNER:-Rashid7226}"
REPO="${PYSCAN_GITHUB_REPO:-pyscan}"
BRANCH="${PYSCAN_GITHUB_BRANCH:-main}"
RAW="https://raw.githubusercontent.com/$OWNER/$REPO/$BRANCH"
DEST="/usr/local/lib/pyscan"
BIN="/usr/local/sbin/pyscan"

[[ $(id -u) -eq 0 ]] || { echo "ERROR: run as root"; exit 1; }
command -v curl >/dev/null || { echo "ERROR: curl is required"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 is required"; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$DEST"
chmod 700 "$DEST"

curl -fL --retry 3 --connect-timeout 10 "$RAW/pyscan.py" -o "$tmp/pyscan.py"
curl -fL --retry 3 --connect-timeout 10 "$RAW/VERSION" -o "$tmp/VERSION"
python3 -m py_compile "$tmp/pyscan.py"

install -m 700 "$tmp/pyscan.py" "$DEST/pyscan.py"
install -m 600 "$tmp/VERSION" "$DEST/VERSION"

cat > "$BIN" <<'EOF'
#!/bin/bash
set -euo pipefail
DEST="/usr/local/lib/pyscan"
if [[ "${1:-}" == "update" ]]; then
  exec bash -c 'curl -fsSL "https://raw.githubusercontent.com/${PYSCAN_GITHUB_OWNER:-Rashid7226}/${PYSCAN_GITHUB_REPO:-pyscan}/${PYSCAN_GITHUB_BRANCH:-main}/install.sh" | bash'
fi
exec python3 "$DEST/pyscan.py" "$@"
EOF
chmod 700 "$BIN"

echo "Pyscan $(cat "$DEST/VERSION") installed."
echo "Run: pyscan -u USERNAME -t 2"
echo "Update: pyscan update"
