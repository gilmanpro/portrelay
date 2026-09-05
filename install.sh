#!/usr/bin/env bash
# Instala portrelay (Linux/macOS) en ~/.local con venv propio.
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PY="${PYTHON:-python3}"
VENV="$HOME/.portrelay/venv"
"$PY" -m venv "$VENV"
"$VENV/bin/pip" -q install --upgrade pip
"$VENV/bin/pip" -q install "$HERE"
mkdir -p "$HOME/.local/bin"
ln -sf "$VENV/bin/portrelay" "$HOME/.local/bin/portrelay"
echo
echo "portrelay instalado: ~/.local/bin/portrelay"
echo 'Si no esta en el PATH:  export PATH="$HOME/.local/bin:$PATH"'
"$VENV/bin/portrelay" --version
