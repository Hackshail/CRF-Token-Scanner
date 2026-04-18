#!/bin/bash
# CSRF Scanner - Build Preparation Script
# Cleans up files before deployment

echo "🧹 Preparing build environment..."

# Remove Python cache files
echo "Removing Python cache files..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "*.pyo" -delete 2>/dev/null || true
find . -name "*$py.class" -delete 2>/dev/null || true

# Remove test and coverage files
echo "Removing test and coverage files..."
rm -rf .pytest_cache/ 2>/dev/null || true
rm -rf htmlcov/ 2>/dev/null || true
rm -rf .tox/ 2>/dev/null || true
rm -rf .nox/ 2>/dev/null || true
rm -f .coverage 2>/dev/null || true
rm -f coverage.xml 2>/dev/null || true

# Remove mypy cache
echo "Removing mypy cache..."
rm -rf .mypy_cache/ 2>/dev/null || true

# Remove old log files (keep recent ones for debugging)
echo "Cleaning up old log files..."
find . -name "csrf_scan_*.log" -type f -mtime +7 -delete 2>/dev/null || true

# Remove virtual environment
echo "Removing virtual environment..."
rm -rf .venv/ 2>/dev/null || true
rm -rf venv/ 2>/dev/null || true

# Remove OS specific files
echo "Removing OS specific files..."
rm -f .DS_Store 2>/dev/null || true
rm -f Thumbs.db 2>/dev/null || true
find . -name "._*" -delete 2>/dev/null || true

# Remove temporary files
echo "Removing temporary files..."
find . -name "*.tmp" -delete 2>/dev/null || true
find . -name "*.temp" -delete 2>/dev/null || true
find . -name "*.bak" -delete 2>/dev/null || true

# Remove runtime generated directories (but keep structure)
echo "Cleaning runtime directories..."
rm -rf scan_results/* 2>/dev/null || true
rm -rf reports/* 2>/dev/null || true
rm -f users.json 2>/dev/null || true

echo "✅ Build environment prepared!"
echo ""
echo "📦 Files that will be included in deployment:"
echo "  - Python source files (*.py)"
echo "  - Templates (templates/*.html)"
echo "  - Configuration files (requirements.txt, render.yaml, etc.)"
echo "  - Documentation (README.md, RENDER_DEPLOYMENT.md)"
echo ""
echo "🚫 Files that will be excluded:"
echo "  - Cache files (__pycache__, *.pyc)"
echo "  - Test artifacts (.pytest_cache, coverage.xml)"
echo "  - Virtual environments (.venv, venv)"
echo "  - Log files (*.log)"
echo "  - OS files (.DS_Store, Thumbs.db)"
echo "  - Runtime data (scan_results, reports, users.json)"