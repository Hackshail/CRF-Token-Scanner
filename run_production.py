#!/usr/bin/env python3
"""
CSRF Scanner - Production Runner
Starts both API server and dashboard
"""

import subprocess
import sys
import time
import os
from pathlib import Path

def check_requirements():
    """Check if required packages are installed"""
    try:
        import flask
        import jwt
        import bcrypt
        import flask_limiter
        import psutil
        print("[OK] All required packages are installed")
        return True
    except ImportError as e:
        print(f"[ERROR] Missing required package: {e}")
        print("Run: pip install -r requirements.txt")
        return False

def start_api_server():
    """Start the API server in background"""
    print("[START] Starting CSRF Scanner API Server...")
    api_process = subprocess.Popen([
        sys.executable, "api_server.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait a bit for server to start
    time.sleep(3)

    # Check if process is still running
    if api_process.poll() is None:
        print("[OK] API Server started successfully on http://localhost:5000")
        return api_process
    else:
        stdout, stderr = api_process.communicate()
        print("[ERROR] Failed to start API Server:")
        print("STDOUT:", stdout.decode())
        print("STDERR:", stderr.decode())
        return None

def start_dashboard():
    """Start the dashboard in background"""
    print("[START] Starting CSRF Scanner Dashboard...")
    dashboard_process = subprocess.Popen([
        sys.executable, "dashboard.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait a bit for server to start
    time.sleep(3)

    # Check if process is still running
    if dashboard_process.poll() is None:
        print("[OK] Dashboard started successfully on http://localhost:3000")
        return dashboard_process
    else:
        stdout, stderr = dashboard_process.communicate()
        print("[ERROR] Failed to start Dashboard:")
        print("STDOUT:", stdout.decode())
        print("STDERR:", stderr.decode())
        return None

def main():
    """Main runner function"""
    print("CSRF Scanner - Production Environment")
    print("=" * 50)

    # Check requirements
    if not check_requirements():
        sys.exit(1)

    # Start API server
    api_process = start_api_server()
    if not api_process:
        print("[ERROR] Cannot continue without API server")
        sys.exit(1)

    # Start dashboard
    dashboard_process = start_dashboard()
    if not dashboard_process:
        print("[WARNING] Dashboard failed to start, but API server is running")
        print("API Server: http://localhost:5000")
        print("Dashboard: Failed to start")
    else:
        print("\n" + "=" * 50)
        print("[SUCCESS] Both services started successfully!")
        print("API Server: http://localhost:5000")
        print("Dashboard: http://localhost:3000")
        print("\nLogin Credentials:")
        print("   Username: admin")
        print("   Password: admin123!")
        print("\n[WARNING] Remember to change default password in production!")
        print("\nPress Ctrl+C to stop all services")

    try:
        # Keep running until interrupted
        while True:
            time.sleep(1)

            # Check if processes are still running
            if api_process.poll() is not None:
                print("[ERROR] API Server has stopped unexpectedly")
                break

            if dashboard_process and dashboard_process.poll() is not None:
                print("[ERROR] Dashboard has stopped unexpectedly")
                break

    except KeyboardInterrupt:
        print("\n[STOP] Shutting down services...")

    finally:
        # Clean up processes
        if api_process and api_process.poll() is None:
            print("Stopping API Server...")
            api_process.terminate()
            api_process.wait(timeout=5)

        if dashboard_process and dashboard_process.poll() is None:
            print("Stopping Dashboard...")
            dashboard_process.terminate()
            dashboard_process.wait(timeout=5)

        print("[OK] All services stopped")

if __name__ == "__main__":
    main()