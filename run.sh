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

VENV_DIR="venv"
PYTHON="$VENV_DIR/bin/python"

# --- Check system Python ---
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.9+ first." >&2
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
echo "[run.sh] Python $PY_VERSION detected"

# --- Migrate a legacy .venv (pre-v2.8.1) in place, packages preserved ---
# Renaming is safe here: the venv python is a symlink to the system
# interpreter and pyvenv.cfg is resolved relative to the binary, so
# "venv/bin/python -m pip" keeps working after the move. This spares
# re-downloading PyQt6 and the screen-channel deps.
if [ ! -d "$VENV_DIR" ] && [ -d ".venv" ]; then
    echo "[run.sh] Found legacy .venv — renaming it to venv ..."
    if mv .venv "$VENV_DIR" 2>/dev/null; then
        echo "[run.sh] Renamed. Installed packages were preserved."
    else
        echo "[run.sh] Rename failed — creating a fresh venv instead."
    fi
fi

# --- Create venv if it doesn't exist, then install requirements ---
FRESH_VENV=false
if [ ! -d "$VENV_DIR" ]; then
    echo "[run.sh] Creating virtual environment at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    FRESH_VENV=true
    echo "[run.sh] Virtual environment created."
fi

# --- Check if --headless flag is passed ---
HEADLESS=false
for arg in "$@"; do
    if [ "$arg" = "--headless" ]; then
        HEADLESS=true
    fi
done

# --- Install required packages ---
# Fresh venv: install everything from requirements.txt right away
# (PyQt6 for the GUI + Pillow/pytesseract/python-xlib for the v2.7
# screen channel). Existing venv in GUI mode: probe PyQt6 and repair
# from requirements.txt if it is missing. Headless mode needs none of
# them at launch time, but a fresh venv is still fully provisioned so
# a later GUI start just works.
if [ "$FRESH_VENV" = true ]; then
    echo "[run.sh] Installing required packages into $VENV_DIR ..."
    if ! "$PYTHON" -m pip install --quiet -r requirements.txt; then
        echo "[run.sh] WARNING: pip install -r requirements.txt failed." >&2
        if [ "$HEADLESS" = false ]; then
            echo "[run.sh] GUI mode needs PyQt6 — fix the install error above and re-run." >&2
            exit 1
        fi
        echo "[run.sh] Continuing in headless mode (standard library only)." >&2
    else
        echo "[run.sh] Requirements installed."
    fi
elif [ "$HEADLESS" = false ]; then
    echo "[run.sh] Checking required packages ..."
    # v2.8.1: probe the full requirements.txt set, not just PyQt6 —
    # the pre-2.8.1 launcher installed PyQt6 alone, so venvs it
    # created lack the v2.7 screen-channel deps (Pillow, pytesseract,
    # python-xlib). find_spec never imports the module, so a broken
    # install still counts as missing and gets repaired.
    MISSING=$("$PYTHON" - <<'PYEOF'
import importlib.util
mods = [("PyQt6", "PyQt6"), ("PIL", "Pillow"),
        ("pytesseract", "pytesseract"), ("Xlib", "python-xlib")]
print(",".join(dist for mod, dist in mods
              if importlib.util.find_spec(mod) is None))
PYEOF
    )
    if [ -n "$MISSING" ]; then
        echo "[run.sh] Missing in venv: $MISSING"
        echo "[run.sh] Reinstalling from requirements.txt ..."
        "$PYTHON" -m pip install --quiet -r requirements.txt
        echo "[run.sh] Requirements installed."
    else
        echo "[run.sh] Required packages already installed."
    fi
fi

# --- Launch ---
echo "[run.sh] Launching host ..."
exec "$PYTHON" host.py "$@"
