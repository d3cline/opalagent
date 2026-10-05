#!/usr/bin/env bash
# Build a standalone executable for the local OS and architecture.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
build_python="${PYTHON:-python3}"
"$build_python" -m venv .build-venv
.build-venv/bin/python -m pip install --upgrade pip
.build-venv/bin/python -m pip install 'pyinstaller>=6,<7' '.[keyring]'
.build-venv/bin/python -m PyInstaller \
  --noconfirm --clean --onefile --name opalagent \
  --paths src --collect-all keyring --collect-all jaraco \
  --exclude-module IPython --exclude-module numpy --exclude-module PIL \
  --exclude-module matplotlib --exclude-module pandas --exclude-module pytest \
  --exclude-module tkinter --exclude-module torch --exclude-module scipy \
  --copy-metadata opalstack --copy-metadata keyring \
  packaging/entrypoint.py
printf '\nBuilt executable: %s/dist/opalagent\n' "$PWD"
dist/opalagent --version
