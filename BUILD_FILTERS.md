# CSRF Scanner - Build Filters Documentation

## Overview
This document explains the include/exclude filters used for deployment and packaging of the CSRF Scanner application.

## Filter Types

### 1. `.gitignore` - Git Repository Control
Controls what files are committed to the repository and thus available for deployment.

**Included in Git:**
- Source code (*.py files)
- Configuration files (render.yaml, requirements.txt, etc.)
- Documentation (README.md, etc.)
- Web templates (templates/*.html)
- Test files (tests/*.py)

**Excluded from Git:**
- Python cache (__pycache__/, *.pyc)
- Virtual environments (.venv/, venv/)
- Test artifacts (.pytest_cache/, coverage.xml)
- Log files (*.log)
- Runtime data (scan_results/, reports/, users.json)
- IDE files (.vscode/, .idea/)
- OS files (.DS_Store, Thumbs.db)

### 2. `.renderignore` - Render Deployment Control
Specific exclusions for Render platform deployment.

**Same as .gitignore but Render-specific:**
- All .gitignore patterns
- Additional deployment-specific exclusions
- Can include/exclude patterns specific to Render builds

### 3. `MANIFEST.in` - Python Package Distribution
Controls what files are included when creating Python packages.

**Include Patterns:**
```
include *.py                    # All Python files
include requirements.txt        # Dependencies
include render.yaml            # Deployment config
recursive-include templates *.html  # Web templates
recursive-include tests *.py   # Test files
```

**Exclude Patterns:**
```
global-exclude *.pyc           # Python cache
global-exclude __pycache__     # Cache directories
prune scan_results            # Runtime data
prune reports                 # Generated reports
```

### 4. `render.yaml` Build Filters
Controls what files are included in the Render build process.

**Include Filters:**
```yaml
buildFilter:
  - include: "*.py"              # Python source
  - include: "templates/**"      # Web templates
  - include: "requirements.txt"  # Dependencies
  - include: "render.yaml"       # This config
  - include: "README.md"         # Documentation
  - include: "tests/**"          # Test files
```

**Exclude Filters:**
```yaml
buildFilter:
  - exclude: "**/__pycache__/**"  # Python cache
  - exclude: "**/*.pyc"          # Compiled Python
  - exclude: "**/*.log"          # Log files
  - exclude: "**/scan_results/**" # Runtime data
  - exclude: "**/.git/**"        # Git repository
```

## Build Process Flow

### 1. Git Commit
```
Local Files → .gitignore → Git Repository
```

### 2. Render Deployment
```
Git Repository → .renderignore → Render Build → buildFilter → Final Deployment
```

### 3. Python Packaging
```
Source Files → MANIFEST.in → Python Package
```

## File Categories

### ✅ Always Included
- `api_server.py` - Main application
- `auth_system.py` - Authentication
- `base_.py` - Scanning engine
- `config.py` - Configuration
- `monitoring.py` - System monitoring
- `templates/*.html` - Web interface
- `requirements.txt` - Dependencies
- `render.yaml` - Deployment config

### ❌ Always Excluded
- `__pycache__/` - Python bytecode cache
- `*.pyc`, `*.pyo` - Compiled Python files
- `.venv/`, `venv/` - Virtual environments
- `*.log` - Log files
- `scan_results/` - Runtime scan data
- `reports/` - Generated reports
- `users.json` - User database
- `.git/` - Git repository data

### 🤔 Conditionally Included
- `tests/` - Included in deployment for CI/CD
- `*.log` - Recent logs may be included for debugging
- `config.local.py` - Never included (local development)

## Build Script

Use `build-clean.sh` to prepare the deployment environment:

```bash
./build-clean.sh
```

This script:
- Removes cache files
- Cleans temporary files
- Prepares the build environment
- Shows what will be included/excluded

## Best Practices

1. **Keep .gitignore Updated** - Add new file types as they appear
2. **Use Build Script** - Run before deployment to ensure clean builds
3. **Monitor Build Size** - Large deployments can slow build times
4. **Test Locally** - Verify filters work as expected
5. **Review Before Commit** - Check what files are being added

## Troubleshooting

### Build Too Large
- Check for large files not in .gitignore
- Remove unnecessary development files
- Clean cache directories

### Missing Files in Deployment
- Check if files are in .gitignore
- Verify render.yaml buildFilter includes pattern
- Ensure files are committed to git

### Cache Files in Deployment
- Run build-clean.sh before deployment
- Check .renderignore patterns
- Verify render.yaml exclude filters