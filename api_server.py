from flask import Flask, render_template, jsonify, request, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import json
import os
import logging
from datetime import datetime
from base_ import CSRFScanner, ScanConfig
from auth_system import auth_manager, require_auth, UserRole, create_rate_limiter
from monitoring import (
    init_monitoring,
    metrics_collector,
    monitor_scan,
    monitor_api_request,
)
import threading
import queue

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Initialize rate limiter
limiter = create_rate_limiter(app)

# Initialize monitoring
init_monitoring(app)

# API Configuration
RESULTS_DIR = "scan_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

# Scan queue for async operations
scan_queue = queue.Queue()
active_scans = {}


@app.route("/api/v1/auth/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    """Authenticate user and return JWT tokens"""
    try:
        data = request.get_json()
        if not data or "username" not in data or "password" not in data:
            return jsonify({"error": "Username and password required"}), 400

        username = data["username"]
        password = data["password"]

        user = auth_manager.authenticate_user(username, password)
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        tokens = auth_manager.generate_tokens(user)

        return (
            jsonify(
                {
                    "message": "Login successful",
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "role": user.role.value,
                        "email": user.email,
                    },
                    **tokens,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Authentication failed"}), 500


@app.route("/api/v1/auth/refresh", methods=["POST"])
@require_auth()
def refresh_token():
    """Refresh access token using refresh token"""
    try:
        data = request.get_json()
        if not data or "refresh_token" not in data:
            return jsonify({"error": "Refresh token required"}), 400

        new_tokens = auth_manager.refresh_access_token(data["refresh_token"])
        if not new_tokens:
            return jsonify({"error": "Invalid refresh token"}), 401

        return jsonify({"message": "Token refreshed successfully", **new_tokens}), 200

    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({"error": "Token refresh failed"}), 500


@app.route("/api/v1/auth/me", methods=["GET"])
@require_auth()
def get_current_user():
    """Get current user information"""
    return jsonify({"user": g.user, "timestamp": datetime.now().isoformat()}), 200


@app.route("/api/v1/scan", methods=["POST"])
@require_auth([UserRole.ADMIN, UserRole.SECURITY_TEAM, UserRole.DEVELOPER])
@limiter.limit("10 per hour")
@monitor_api_request("start_scan")
def start_scan():
    """Start a new CSRF vulnerability scan"""
    try:
        data = request.json

        # Validate input
        if not data or "url" not in data:
            return jsonify({"error": "URL is required"}), 400

        url = data["url"]
        depth = data.get("depth", 2)
        scan_id = data.get("scan_id", f"scan_{datetime.now().timestamp()}")

        # Validate URL format
        if not url.startswith(("http://", "https://")):
            return jsonify({"error": "URL must start with http:// or https://"}), 400

        # Create config
        config = ScanConfig()
        config.timeout = data.get("timeout", 15)
        config.max_urls = data.get("max_urls", 100)
        config.verify_ssl = data.get("verify_ssl", True)

        # Start scan in background
        scanner = CSRFScanner(url, depth=depth, config=config)
        active_scans[scan_id] = {
            "status": "running",
            "start_time": datetime.now(),
            "results": None,
            "scanner": scanner,
            "user": g.user["username"],
        }

        # Start scan in thread
        thread = threading.Thread(
            target=_run_scan, args=(scan_id, scanner), daemon=True
        )
        thread.start()

        logger.info(f"Scan {scan_id} started for {url} by user {g.user['username']}")

        return (
            jsonify(
                {
                    "scan_id": scan_id,
                    "status": "started",
                    "message": "Scan started successfully",
                }
            ),
            202,
        )

    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({"error": "Failed to start scan"}), 500


@app.route("/api/v1/scan/<scan_id>", methods=["GET"])
@require_auth(
    [UserRole.ADMIN, UserRole.SECURITY_TEAM, UserRole.DEVELOPER, UserRole.AUDITOR]
)
@limiter.limit("100 per hour")
def get_scan_status(scan_id):
    """Get scan status and results"""
    # Check if user can access this scan
    scan_info = active_scans.get(scan_id)
    if not scan_info:
        return jsonify({"error": "Scan not found"}), 404

    # Only admin and security team can see all scans, others can only see their own
    if g.user["role"] not in [UserRole.ADMIN.value, UserRole.SECURITY_TEAM.value]:
        if scan_info.get("user") != g.user["username"]:
            return jsonify({"error": "Access denied"}), 403

    return (
        jsonify(
            {
                "scan_id": scan_id,
                "status": scan_info["status"],
                "start_time": scan_info["start_time"].isoformat(),
                "results_count": (
                    len(scan_info["results"]) if scan_info["results"] else 0
                ),
                "results": scan_info["results"],
            }
        ),
        200,
    )


@app.route("/api/v1/scan/<scan_id>/results", methods=["GET"])
@require_auth(
    [UserRole.ADMIN, UserRole.SECURITY_TEAM, UserRole.DEVELOPER, UserRole.AUDITOR]
)
@limiter.limit("100 per hour")
def get_scan_results(scan_id):
    """Get detailed scan results with filtering"""
    scan_info = active_scans.get(scan_id)
    if not scan_info:
        return jsonify({"error": "Scan not found"}), 404

    # Check access permissions
    if g.user["role"] not in [UserRole.ADMIN.value, UserRole.SECURITY_TEAM.value]:
        if scan_info.get("user") != g.user["username"]:
            return jsonify({"error": "Access denied"}), 403

    results = scan_info["results"]

    if results is None:
        return jsonify({"error": "Scan not completed"}), 202

    # Apply filters
    filter_status = request.args.get("status")
    filter_risk = request.args.get("risk_level")

    filtered_results = results
    if filter_status:
        filtered_results = [
            r for r in filtered_results if r.get("status") == filter_status
        ]
    if filter_risk:
        filtered_results = [
            r for r in filtered_results if r.get("risk_level") == filter_risk
        ]

    # Generate summary
    summary = {
        "total_forms": len(results),
        "vulnerable_forms": len([r for r in results if r["status"] != "safe"]),
        "critical_forms": len(
            [r for r in results if r.get("risk_level") == "critical"]
        ),
        "high_risk_forms": len([r for r in results if r.get("risk_level") == "high"]),
    }

    return (
        jsonify({"scan_id": scan_id, "summary": summary, "results": filtered_results}),
        200,
    )


@app.route("/api/v1/scan/<scan_id>", methods=["DELETE"])
@require_auth([UserRole.ADMIN, UserRole.SECURITY_TEAM])
@limiter.limit("50 per hour")
def cancel_scan(scan_id):
    """Cancel an active scan"""
    scan_info = active_scans.get(scan_id)
    if not scan_info:
        return jsonify({"error": "Scan not found"}), 404

    # Only admin, security team, or scan owner can cancel
    if g.user["role"] not in [UserRole.ADMIN.value, UserRole.SECURITY_TEAM.value]:
        if scan_info.get("user") != g.user["username"]:
            return jsonify({"error": "Access denied"}), 403

    if scan_info["status"] == "running":
        scan_info["status"] = "cancelled"
        logger.info(f"Scan {scan_id} cancelled by user {g.user['username']}")

    return jsonify({"message": "Scan cancelled"}), 200


@app.route("/api/v1/scans", methods=["GET"])
@require_auth(
    [UserRole.ADMIN, UserRole.SECURITY_TEAM, UserRole.DEVELOPER, UserRole.AUDITOR]
)
@limiter.limit("100 per hour")
def list_scans():
    """List all scans with their status"""
    scans_list = []

    for scan_id, scan_info in active_scans.items():
        # Filter scans based on user permissions
        if g.user["role"] not in [UserRole.ADMIN.value, UserRole.SECURITY_TEAM.value]:
            if scan_info.get("user") != g.user["username"]:
                continue  # Skip scans that don't belong to this user

        scans_list.append(
            {
                "scan_id": scan_id,
                "status": scan_info["status"],
                "start_time": scan_info["start_time"].isoformat(),
                "results_count": (
                    len(scan_info["results"]) if scan_info["results"] else 0
                ),
                "user": scan_info.get("user", "unknown"),
            }
        )

    return jsonify({"scans": scans_list, "total": len(scans_list)}), 200


# Simple dashboard integration - replace API docs with dashboard redirect
@app.route("/", methods=["GET"])
def index():
    """Serve dashboard or redirect to login"""
    return "Server is up and running!"


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500


@monitor_scan
def _run_scan(scan_id, scanner):
    """Background function to run scan"""
    try:
        results = scanner.scan()
        active_scans[scan_id]["results"] = results
        active_scans[scan_id]["status"] = "completed"
        logger.info(f"Scan {scan_id} completed with {len(results)} results")
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["results"] = {"error": str(e)}


# Dashboard Routes - Integrated into API Server
from flask import render_template, redirect, url_for, flash, session
import requests
from datetime import datetime, timedelta
from functools import wraps

# Dashboard Configuration
app.secret_key = os.getenv("SECRET_KEY", "change-this-in-production-dashboard")
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:5000")

# Session configuration
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)


def login_required(f):
    """Decorator to require login for dashboard access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "access_token" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def api_request(method, endpoint, data=None, headers=None):
    """Make authenticated API request"""
    url = f"{API_BASE_URL}{endpoint}"
    default_headers = {}

    if "access_token" in session:
        default_headers["Authorization"] = f"Bearer {session['access_token']}"

    if headers:
        default_headers.update(headers)

    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=default_headers)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=default_headers)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=default_headers)
        else:
            return None

        return response
    except requests.RequestException as e:
        logger.error(f"API request failed: {e}")
        return None


@app.route("/")
def index():
    """Dashboard home page"""
    if "access_token" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("login.html")

        # Authenticate via API
        response = api_request("POST", "/api/v1/auth/login", {
            "username": username,
            "password": password
        })

        if response and response.status_code == 200:
            data = response.json()
            session["access_token"] = data.get("access_token")
            session["refresh_token"] = data.get("refresh_token")
            session["user"] = data.get("user")
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logout user"""
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    """Main dashboard page"""
    return render_template("dashboard.html")


@app.route("/api/dashboard/stats")
@login_required
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Get scan statistics
        scans_response = api_request("GET", "/api/v1/scans")
        scans_data = scans_response.json() if scans_response else {"scans": []}

        # Calculate statistics
        total_scans = len(scans_data.get("scans", []))
        completed_scans = len([s for s in scans_data.get("scans", []) if s.get("status") == "completed"])
        failed_scans = len([s for s in scans_data.get("scans", []) if s.get("status") == "failed"])
        active_scans = len([s for s in scans_data.get("scans", []) if s.get("status") == "running"])

        return jsonify({
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "active_scans": active_scans
        })
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({"error": "Failed to get statistics"}), 500


@app.route("/scans")
@login_required
def scans():
    """Scans management page"""
    return render_template("scans.html")


@app.route("/api/scans")
@login_required
def get_scans():
    """Get all scans"""
    response = api_request("GET", "/api/v1/scans")
    if response:
        return response.json()
    return jsonify({"scans": []})


@app.route("/scan/new", methods=["GET", "POST"])
@login_required
def new_scan():
    """Create new scan"""
    if request.method == "POST":
        url = request.form.get("url")
        depth = int(request.form.get("depth", 2))
        max_urls = int(request.form.get("max_urls", 100))

        if not url:
            flash("URL is required", "error")
            return render_template("new_scan.html")

        # Create scan via API
        response = api_request("POST", "/api/v1/scans", {
            "url": url,
            "depth": depth,
            "max_urls": max_urls
        })

        if response and response.status_code == 201:
            data = response.json()
            scan_id = data.get("scan_id")
            flash("Scan started successfully!", "success")
            return redirect(url_for("scan_detail", scan_id=scan_id))
        else:
            flash("Failed to start scan", "error")

    return render_template("new_scan.html")


@app.route("/scan/<scan_id>")
@login_required
def scan_detail(scan_id):
    """Scan detail page"""
    return render_template("scan_detail.html", scan_id=scan_id)


@app.route("/api/scan/<scan_id>")
@login_required
def get_scan(scan_id):
    """Get scan details"""
    response = api_request("GET", f"/api/v1/scans/{scan_id}")
    if response:
        return response.json()
    return jsonify({"error": "Scan not found"}), 404


@app.route("/api/scan/<scan_id>/results")
@login_required
def get_scan_results(scan_id):
    """Get scan results"""
    response = api_request("GET", f"/api/v1/scans/{scan_id}/results")
    if response:
        return response.json()
    return jsonify({"error": "Results not found"}), 404


@app.route("/api/scan/<scan_id>/cancel", methods=["POST"])
@login_required
def cancel_scan(scan_id):
    """Cancel a running scan"""
    response = api_request("POST", f"/api/v1/scans/{scan_id}/cancel")
    if response and response.status_code == 200:
        return jsonify({"message": "Scan cancelled successfully"})
    return jsonify({"error": "Failed to cancel scan"}), 400


@app.route("/monitoring")
@login_required
def monitoring():
    """Monitoring page"""
    return render_template("monitoring.html")


@app.route("/api/dashboard/metrics")
@login_required
def get_metrics():
    """Get system metrics"""
    response = api_request("GET", "/api/v1/monitoring/metrics")
    if response:
        return response.json()
    return jsonify({"error": "Metrics not available"}), 500


@app.route("/api/monitoring/health")
@login_required
def health_check():
    """Health check endpoint"""
    response = api_request("GET", "/api/v1/monitoring/health")
    if response:
        return response.json()
    return jsonify({"status": "unknown"}), 500


@app.route("/api/v1/health")
def health_check():
    """Health check endpoint for Render"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
