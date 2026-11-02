# run.ps1 — LLM Directory Bridge launcher (Windows / PowerShell)
#
# Detects or creates a virtual environment, installs requirements,
# then launches the PyQt6 GUI.
#
# Usage:
#   .\run.ps1              # launch GUI
#   .\run.ps1 -Headless   # launch headless (no GUI, no PyQt6 needed)
#   .\run.ps1 -Dir C:\path # pre-set shared directory

param(
    [string[]]$Args
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

$VenvDir = ".venv"
$Python = "$VenvDir\Scripts\python.exe"

# --- Check system Python ---
try {
    $pyVersion = & python --version 2>&1
    Write-Host "[run.ps1] $pyVersion detected"
} catch {
    Write-Error "ERROR: python not found. Install Python 3.9+ first."
    exit 1
}

# --- Create venv if it doesn't exist ---
if (-not (Test-Path $VenvDir)) {
    Write-Host "[run.ps1] Creating virtual environment at $VenvDir ..."
    & python -m venv $VenvDir
    Write-Host "[run.ps1] Virtual environment created."
}

# --- Check if --Headless flag is passed ---
$Headless = $false
foreach ($arg in $Args) {
    if ($arg -eq "--headless" -or $arg -eq "-Headless") {
        $Headless = $true
    }
}

# --- Install PyQt6 if GUI mode ---
if (-not $Headless) {
    Write-Host "[run.ps1] Checking PyQt6 ..."
    $pyqtCheck = & $Python -c "import PyQt6" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[run.ps1] PyQt6 not found in venv. Installing ..."
        & $Python -m pip install --quiet PyQt6
        Write-Host "[run.ps1] PyQt6 installed."
    } else {
        Write-Host "[run.ps1] PyQt6 already installed."
    }
}

# --- Launch ---
Write-Host "[run.ps1] Launching host ..."
& $Python host.py @Args
