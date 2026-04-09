# Lazy Panda v8.0.0 - Windows PowerShell Installation Script
# Author: Ian Carter Kulani

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         LAZY PANDA v8.0.0 - Windows Installation          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check Python installation
Write-Host "[1/6] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python 3\.[7-9]|3\.[1-9][0-9]") {
        Write-Host "✓ $pythonVersion found" -ForegroundColor Green
    } else {
        Write-Host "✗ Python 3.7+ required. Download from https://python.org" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "✗ Python not found. Please install Python 3.7 or higher" -ForegroundColor Red
    Write-Host "  Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Check pip
Write-Host "`n[2/6] Checking pip..." -ForegroundColor Yellow
try {
    pip --version 2>&1 | Out-Null
    Write-Host "✓ pip found" -ForegroundColor Green
} catch {
    Write-Host "✗ pip not found. Installing..." -ForegroundColor Yellow
    python -m ensurepip --upgrade
}

# Create virtual environment
Write-Host "`n[3/6] Setting up virtual environment..." -ForegroundColor Yellow
$createVenv = Read-Host "Create virtual environment? (y/n)"
if ($createVenv -eq 'y') {
    python -m venv lazy_panda_env
    & .\lazy_panda_env\Scripts\Activate.ps1
    Write-Host "✓ Virtual environment created and activated" -ForegroundColor Green
} else {
    Write-Host "ℹ Skipping virtual environment" -ForegroundColor Blue
}

# Install dependencies
Write-Host "`n[4/6] Installing Python dependencies..." -ForegroundColor Yellow
if (Test-Path "requirements.txt") {
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    Write-Host "✓ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "✗ requirements.txt not found" -ForegroundColor Red
    exit 1
}

# Create directories
Write-Host "`n[5/6] Creating directories..." -ForegroundColor Yellow
$directories = @(
    ".lazy_panda",
    "lazy_panda_reports",
    "lazy_panda_reports\scans",
    "lazy_panda_reports\blocked",
    "lazy_panda_reports\graphics",
    "lazy_panda_temp"
)

foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Host "✓ Directories created" -ForegroundColor Green

# Create launcher batch file
Write-Host "`n[6/6] Creating launcher script..." -ForegroundColor Yellow
$launcherContent = @'
@echo off
cd /d "%~dp0"
if exist "lazy_panda_env\Scripts\activate.bat" (
    call lazy_panda_env\Scripts\activate.bat
)
python lazy_panda.py %*
'@

$launcherContent | Out-File -FilePath "lazy_panda_launcher.bat" -Encoding ASCII
Write-Host "✓ Launcher created: lazy_panda_launcher.bat" -ForegroundColor Green

# Final message
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              INSTALLATION COMPLETED SUCCESSFULLY!              ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "To start Lazy Panda:" -ForegroundColor Yellow
Write-Host "  .\lazy_panda_launcher.bat" -ForegroundColor Cyan
Write-Host ""
Write-Host "Or directly:" -ForegroundColor Yellow
Write-Host "  python lazy_panda.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "For Discord bot integration:" -ForegroundColor Yellow
Write-Host "  1. Create a bot at https://discord.com/developers/applications" -ForegroundColor Blue
Write-Host "  2. Run setup and configure Discord token" -ForegroundColor Blue
Write-Host ""
Read-Host "Press Enter to exit"