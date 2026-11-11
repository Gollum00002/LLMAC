# run.ps1 — LLM Directory Bridge launcher (Windows / PowerShell)
#
# Detects or creates a virtual environment, installs requirements,
# then launches the PyQt6 GUI.
#
# Usage:
#   .\run.ps1              # launch GUI
#   .\run.ps1 --headless   # launch headless (no GUI, no PyQt6 needed)
#   .\run.ps1 --dir C:\path # pre-set shared directory

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

# v2.8.1: the venv directory is "venv" (was ".venv"). No param()
# block on purpose — all script arguments are forwarded verbatim to
# host.py via the automatic $args variable.
$VenvDir = "venv"
$Python = "$VenvDir\Scripts\python.exe"

# --- Check system Python ---
# NB: redirected native stderr under EAP=Stop wraps into a terminating
# error on PS 5.1, so version probes run with EAP=Continue and exit
# codes are checked explicitly.
$ErrorActionPreference = "Continue"
try {
    $pyVersion = & python --version 2>&1
} catch {
    $pyVersion = $null
}
if ($null -eq $pyVersion -or $LASTEXITCODE -ne 0) {
    Write-Host "ERROR: python not found. Install Python 3.9+ first."
    exit 1
}
$ErrorActionPreference = "Stop"
Write-Host "[run.ps1] $pyVersion detected"

# --- Migrate a legacy .venv (pre-v2.8.1) in place, packages preserved ---
# Renaming is safe: the venv python is a launcher whose pyvenv.cfg is
# resolved relative to the binary, and we only ever call it as
# "venv\Scripts\python.exe -m pip", so the move spares re-downloading
# PyQt6 and the screen-channel deps.
if (-not (Test-Path $VenvDir) -and (Test-Path ".venv")) {
    Write-Host "[run.ps1] Found legacy .venv — renaming it to venv ..."
    try {
        Rename-Item -Path ".venv" -NewName $VenvDir -ErrorAction Stop
        Write-Host "[run.ps1] Renamed. Installed packages were preserved."
    } catch {
        Write-Host "[run.ps1] Rename failed — creating a fresh venv instead."
    }
}

# --- Create venv if it doesn't exist ---
$FreshVenv = $false
if (-not (Test-Path $VenvDir)) {
    Write-Host "[run.ps1] Creating virtual environment at $VenvDir ..."
    & python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "ERROR: failed to create the virtual environment."
        exit 1
    }
    $FreshVenv = $true
    Write-Host "[run.ps1] Virtual environment created."
}

# --- Check if --headless flag is passed ---
$Headless = $false
foreach ($arg in $args) {
    if ($arg -eq "--headless" -or $arg -eq "-Headless") {
        $Headless = $true
    }
}

# --- Install required packages ---
# Fresh venv: install everything from requirements.txt right away
# (PyQt6 for the GUI + Pillow/pytesseract/python-xlib for the v2.7
# screen channel). Existing venv in GUI mode: probe PyQt6 and repair
# from requirements.txt if it is missing. Headless mode needs none of
# them at launch time, but a fresh venv is still fully provisioned so
# a later GUI start just works.
if ($FreshVenv) {
    Write-Host "[run.ps1] Installing required packages into $VenvDir ..."
    & $Python -m pip install --quiet -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[run.ps1] WARNING: pip install -r requirements.txt failed."
        if (-not $Headless) {
            Write-Error "[run.ps1] GUI mode needs PyQt6 — fix the install error above and re-run."
            exit 1
        }
        Write-Host "[run.ps1] Continuing in headless mode (standard library only)."
    } else {
        Write-Host "[run.ps1] Requirements installed."
    }
} elseif (-not $Headless) {
    Write-Host "[run.ps1] Checking required packages ..."
    # v2.8.1: probe the full requirements.txt set, not just PyQt6 —
    # the pre-2.8.1 launcher installed PyQt6 alone, so venvs it
    # created lack the v2.7 screen-channel deps. find_spec never
    # imports the module, so a broken install still counts as
    # missing and gets repaired.
    $ErrorActionPreference = "Continue"
    $probe = @'
import importlib.util
mods = [("PyQt6", "PyQt6"), ("PIL", "Pillow"),
        ("pytesseract", "pytesseract"), ("Xlib", "python-xlib")]
print(",".join(dist for mod, dist in mods
              if importlib.util.find_spec(mod) is None))
'@
    $missing = "$(& $Python -c $probe 2>&1)"
    $probeFailed = ($LASTEXITCODE -ne 0)
    $ErrorActionPreference = "Stop"
    if ($probeFailed -or $missing) {
        if ($missing) { Write-Host "[run.ps1] Missing in venv: $missing" }
        Write-Host "[run.ps1] Reinstalling from requirements.txt ..."
        & $Python -m pip install --quiet -r requirements.txt
        if ($LASTEXITCODE -ne 0) {
            Write-Error "[run.ps1] pip install failed — fix the install error above and re-run."
            exit 1
        }
        Write-Host "[run.ps1] Requirements installed."
    } else {
        Write-Host "[run.ps1] Required packages already installed."
    }
}

# --- Launch ---
Write-Host "[run.ps1] Launching host ..."
& $Python host.py @args
