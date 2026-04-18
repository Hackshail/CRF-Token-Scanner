# CSRF Scanner - Build Preparation Script (PowerShell)
# Cleans up files before deployment on Windows

Write-Host "🧹 Preparing build environment..." -ForegroundColor Green

# Remove Python cache files
Write-Host "Removing Python cache files..." -ForegroundColor Yellow
Get-ChildItem -Path . -Recurse -Directory -Name "__pycache__" | ForEach-Object {
    Remove-Item -Path $_ -Recurse -Force -ErrorAction SilentlyContinue
}
Get-ChildItem -Path . -Recurse -File -Include "*.pyc", "*.pyo", "*`$py.class" | Remove-Item -Force -ErrorAction SilentlyContinue

# Remove test and coverage files
Write-Host "Removing test and coverage files..." -ForegroundColor Yellow
Remove-Item -Path ".pytest_cache" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "htmlcov" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path ".tox" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path ".nox" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path ".coverage" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "coverage.xml" -Force -ErrorAction SilentlyContinue

# Remove mypy cache
Write-Host "Removing mypy cache..." -ForegroundColor Yellow
Remove-Item -Path ".mypy_cache" -Recurse -Force -ErrorAction SilentlyContinue

# Remove old log files (keep recent ones for debugging)
Write-Host "Cleaning up old log files..." -ForegroundColor Yellow
Get-ChildItem -Path . -File -Filter "csrf_scan_*.log" | Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddDays(-7)
} | Remove-Item -Force -ErrorAction SilentlyContinue

# Remove virtual environment
Write-Host "Removing virtual environment..." -ForegroundColor Yellow
Remove-Item -Path ".venv" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "venv" -Recurse -Force -ErrorAction SilentlyContinue

# Remove OS specific files
Write-Host "Removing OS specific files..." -ForegroundColor Yellow
Remove-Item -Path ".DS_Store" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "Thumbs.db" -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path . -File -Filter "._*" | Remove-Item -Force -ErrorAction SilentlyContinue

# Remove temporary files
Write-Host "Removing temporary files..." -ForegroundColor Yellow
Get-ChildItem -Path . -File -Filter "*.tmp" | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path . -File -Filter "*.temp" | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path . -File -Filter "*.bak" | Remove-Item -Force -ErrorAction SilentlyContinue

# Remove runtime generated directories (but keep structure)
Write-Host "Cleaning runtime directories..." -ForegroundColor Yellow
if (Test-Path "scan_results") {
    Get-ChildItem -Path "scan_results" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
if (Test-Path "reports") {
    Get-ChildItem -Path "reports" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item -Path "users.json" -Force -ErrorAction SilentlyContinue

Write-Host "✅ Build environment prepared!" -ForegroundColor Green
Write-Host ""
Write-Host "📦 Files that will be included in deployment:" -ForegroundColor Cyan
Write-Host "  - Python source files (*.py)" -ForegroundColor White
Write-Host "  - Templates (templates/*.html)" -ForegroundColor White
Write-Host "  - Configuration files (requirements.txt, render.yaml, etc.)" -ForegroundColor White
Write-Host "  - Documentation (README.md, RENDER_DEPLOYMENT.md)" -ForegroundColor White
Write-Host ""
Write-Host "🚫 Files that will be excluded:" -ForegroundColor Red
Write-Host "  - Cache files (__pycache__, *.pyc)" -ForegroundColor White
Write-Host "  - Test artifacts (.pytest_cache, coverage.xml)" -ForegroundColor White
Write-Host "  - Virtual environments (.venv, venv)" -ForegroundColor White
Write-Host "  - Log files (*.log)" -ForegroundColor White
Write-Host "  - OS files (.DS_Store, Thumbs.db)" -ForegroundColor White
Write-Host "  - Runtime data (scan_results, reports, users.json)" -ForegroundColor White