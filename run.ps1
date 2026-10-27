$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path '.venv\Scripts\python.exe')) {
    Write-Host '[KlyPen] Creating Python virtual environment...'
    py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the virtual environment. Install Python 3.10+ and retry.' }
    & .\.venv\Scripts\python.exe -m pip install --upgrade pip
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
}
if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    Write-Host '[KlyPen] Created .env from .env.example. Review it before adding optional keys.'
}
Write-Host ''
Write-Host 'KlyPen will be available at http://127.0.0.1:8000'
Write-Host 'Press Ctrl+C to stop.'
& .\.venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
