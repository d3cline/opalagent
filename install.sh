#!/usr/bin/env bash
set -euo pipefail

REPO="d3cline/opalagent"
BIN_DIR="${OPALAGENT_BIN_DIR:-$HOME/.local/bin}"
APP_DIR="${OPALAGENT_HOME:-$HOME/.local/share/opalagent}"
PYTHON="${PYTHON:-python3}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"

say() { printf '%s\n' "$*"; }
fail() { printf 'opalagent: %s\n' "$*" >&2; exit 1; }

mkdir -p "$BIN_DIR"

# If this checkout already contains a freshly built standalone binary, use it.
if [[ -n "$ROOT" && -x "$ROOT/dist/opalagent" ]]; then
  install -m 755 "$ROOT/dist/opalagent" "$BIN_DIR/opalagent"
  say "Installed $BIN_DIR/opalagent"
  exit 0
fi

command -v "$PYTHON" >/dev/null 2>&1 || fail "Python 3.10+ is required for the portable source install."
"$PYTHON" - <<'PY' || exit 1
import sys
if sys.version_info < (3, 10):
    raise SystemExit("opalagent requires Python 3.10+")
PY

mkdir -p "$APP_DIR"
VENV="$APP_DIR/venv"
"$PYTHON" -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip >/dev/null

if [[ -n "$ROOT" && -f "$ROOT/pyproject.toml" ]]; then
  say "Installing OpalAgent from local checkout..."
  "$VENV/bin/python" -m pip install --upgrade "${ROOT}[keyring]"
else
  say "Installing OpalAgent from GitHub..."
  "$VENV/bin/python" -m pip install --upgrade "opalagent[keyring] @ https://github.com/${REPO}/archive/refs/heads/main.zip"
fi

ln -sfn "$VENV/bin/opalagent" "$BIN_DIR/opalagent"
say "Installed $BIN_DIR/opalagent"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "Add $BIN_DIR to PATH, then run: opalagent" ;;
esac
