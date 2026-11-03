#!/usr/bin/env bash
# run.sh — LLM Directory Bridge launcher (Linux / macOS)
#
# Detects or creates a virtual environment, installs requirements,
# then launches the PyQt6 GUI.
#
# Usage:
#   ./run.sh              # launch GUI
#   ./run.sh --headless   # launch headless (no GUI, no PyQt6 needed)
#   ./run.sh --dir /path  # pre-set shared directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"
PYTHON="$VENV_DIR/bin/python"

# --- Check system Python ---
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.9+ first." >&2
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
echo "[run.sh] Python $PY_VERSION detected"

# --- Create venv if it doesn't exist ---
if [ ! -d "$VENV_DIR" ]; then
    echo "[run.sh] Creating virtual environment at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    echo "[run.sh] Virtual environment created."
fi

# --- Check if PyQt6 is installed (unless --headless) ---
HEADLESS=false
for arg in "$@"; do
    if [ "$arg" = "--headless" ]; then
        HEADLESS=true
    fi
done

if [ "$HEADLESS" = false ]; then
    echo "[run.sh] Checking PyQt6 ..."
    if ! "$PYTHON" -c "import PyQt6" 2>/dev/null; then
        echo "[run.sh] PyQt6 not found in venv. Installing ..."
        "$PYTHON" -m pip install --quiet PyQt6
        echo "[run.sh] PyQt6 installed."
    else
        echo "[run.sh] PyQt6 already installed."
    fi
fi

# --- Check if llmac.py's deps are all stdlib (they are, but verify) ---
echo "[run.sh] Launching host ..."
exec "$PYTHON" host.py "$@"
