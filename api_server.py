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
from monitoring import init_monitoring, metrics_collector, monitor_scan, monitor_api_request
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
RESULTS_DIR = 'scan_results'
os.makedirs(RESULTS_DIR, exist_ok=True)

# Scan queue for async operations
scan_queue = queue.Queue()
active_scans = {}


@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Authenticate user and return JWT tokens"""
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password required'}), 400

        username = data['username']
        password = data['password']

        user = auth_manager.authenticate_user(username, password)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        tokens = auth_manager.generate_tokens(user)

        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role.value,
                'email': user.email
            },
            **tokens
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500


@app.route('/api/v1/auth/refresh', methods=['POST'])
@require_auth()
def refresh_token():
    """Refresh access token using refresh token"""
    try:
        data = request.get_json()
        if not data or 'refresh_token' not in data:
            return jsonify({'error': 'Refresh token required'}), 400

        new_tokens = auth_manager.refresh_access_token(data['refresh_token'])
        if not new_tokens:
            return jsonify({'error': 'Invalid refresh token'}), 401

        return jsonify({
            'message': 'Token refreshed successfully',
            **new_tokens
        }), 200

    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500


@app.route('/api/v1/auth/me', methods=['GET'])
@require_auth()
def get_current_user():
    """Get current user information"""
    return jsonify({
        'user': g.user,
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/v1/scan', methods=['POST'])
@require_auth([UserRole.ADMIN, UserRole.SECURITY_TEAM, UserRole.DEVELOPER])
@limiter.limit("10 per hour")
@monitor_api_request('start_scan')
def start_scan():
    """Start a new CSRF vulnerability scan"""
    try:
        data = request.json

        # Validate input
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url']
        depth = data.get('depth', 2)
        scan_id = data.get('scan_id', f"scan_{datetime.now().timestamp()}")

        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'URL must start with http:// or https://'}), 400

        # Create config
        config = ScanConfig()
        config.timeout = data.get('timeout', 15)
        config.max_urls = data.get('max_urls', 100)
        config.verify_ssl = data.get('verify_ssl', True)

        # Start scan in background
        scanner = CSRFScanner(url, depth=depth, config=config)
        active_scans[scan_id] = {
            'status': 'running',
            'start_time': datetime.now(),
            'results': None,
            'scanner': scanner,
            'user': g.user['username']
        }

        # Start scan in thread
        thread = threading.Thread(
            target=_run_scan,
            args=(scan_id, scanner),
            daemon=True
        )
        thread.start()

        logger.info(f"Scan {scan_id} started for {url} by user {g.user['username']}")

        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': 'Scan started successfully'
        }), 202

    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': 'Failed to start scan'}), 500


@app.route('/api/v1/scan/<scan_id>', methods=['GET'])
@require_auth([UserRole.ADMIN, UserRole.SECURITY_TEAM, UserRole.DEVELOPER, UserRole.AUDITOR])
@limiter.limit("100 per hour")
def get_scan_status(scan_id):
    """Get scan status and results"""
    # Check if user can access this scan
    scan_info = active_scans.get(scan_id)
    if not scan_info:
        return jsonify({'error': 'Scan not found'}), 404

    # Only admin and security team can see all scans, others can only see their own
    if g.user['role'] not in [UserRole.ADMIN.value, UserRole.SECURITY_TEAM.value]:
        if scan_info.get('user') != g.user['username']:
            return jsonify({'error': 'Access denied'}), 403

    return jsonify({
        'scan_id': scan_id,
        'status': scan_info['status'],
        'start_time': scan_info['start_time'].isoformat(),
        'results_count': len(scan_info['results']) if scan_info['results'] else 0,
        'results': scan_info['results']
    }), 200


@app.route('/api/v1/scan/<scan_id>/results', methods=['GET'])
@require_auth([UserRole.ADMIN, UserRole.SECURITY_TEAM, UserRole.DEVELOPER, UserRole.AUDITOR])
@limiter.limit("100 per hour")
def get_scan_results(scan_id):
    """Get detailed scan results with filtering"""
    scan_info = active_scans.get(scan_id)
    if not scan_info:
        return jsonify({'error': 'Scan not found'}), 404

    # Check access permissions
    if g.user['role'] not in [UserRole.ADMIN.value, UserRole.SECURITY_TEAM.value]:
        if scan_info.get('user') != g.user['username']:
            return jsonify({'error': 'Access denied'}), 403

    results = scan_info['results']

    if results is None:
        return jsonify({'error': 'Scan not completed'}), 202

    # Apply filters
    filter_status = request.args.get('status')
    filter_risk = request.args.get('risk_level')

    filtered_results = results
    if filter_status:
        filtered_results = [r for r in filtered_results if r.get('status') == filter_status]
    if filter_risk:
        filtered_results = [r for r in filtered_results if r.get('risk_level') == filter_risk]

    # Generate summary
    summary = {
        'total_forms': len(results),
        'vulnerable_forms': len([r for r in results if r['status'] != 'safe']),
        'critical_forms': len([r for r in results if r.get('risk_level') == 'critical']),
        'high_risk_forms': len([r for r in results if r.get('risk_level') == 'high'])
    }

    return jsonify({
        'scan_id': scan_id,
        'summary': summary,
        'results': filtered_results
    }), 200


@app.route('/api/v1/scan/<scan_id>', methods=['DELETE'])
@require_auth([UserRole.ADMIN, UserRole.SECURITY_TEAM])
@limiter.limit("50 per hour")
def cancel_scan(scan_id):
    """Cancel an active scan"""
    scan_info = active_scans.get(scan_id)
    if not scan_info:
        return jsonify({'error': 'Scan not found'}), 404

    # Only admin, security team, or scan owner can cancel
    if g.user['role'] not in [UserRole.ADMIN.value, UserRole.SECURITY_TEAM.value]:
        if scan_info.get('user') != g.user['username']:
            return jsonify({'error': 'Access denied'}), 403

    if scan_info['status'] == 'running':
        scan_info['status'] = 'cancelled'
        logger.info(f"Scan {scan_id} cancelled by user {g.user['username']}")

    return jsonify({'message': 'Scan cancelled'}), 200


@app.route('/api/v1/scans', methods=['GET'])
@require_auth([UserRole.ADMIN, UserRole.SECURITY_TEAM, UserRole.DEVELOPER, UserRole.AUDITOR])
@limiter.limit("100 per hour")
def list_scans():
    """List all scans with their status"""
    scans_list = []

    for scan_id, scan_info in active_scans.items():
        # Filter scans based on user permissions
        if g.user['role'] not in [UserRole.ADMIN.value, UserRole.SECURITY_TEAM.value]:
            if scan_info.get('user') != g.user['username']:
                continue  # Skip scans that don't belong to this user

        scans_list.append({
            'scan_id': scan_id,
            'status': scan_info['status'],
            'start_time': scan_info['start_time'].isoformat(),
            'results_count': len(scan_info['results']) if scan_info['results'] else 0,
            'user': scan_info.get('user', 'unknown')
        })

    return jsonify({'scans': scans_list, 'total': len(scans_list)}), 200


# Simple dashboard integration - replace API docs with dashboard redirect
@app.route('/', methods=['GET'])
def index():
    """Serve dashboard or redirect to login"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSRF Scanner Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .login-form { max-width: 400px; margin: 20px auto; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .api-info { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 CSRF Vulnerability Scanner</h1>
            <p style="text-align: center; color: #666;">Production-ready web application security assessment tool</p>

            <div class="login-form">
                <h3>Dashboard Login</h3>
                <form action="/api/v1/auth/login" method="post">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
                <p style="text-align: center; margin-top: 10px; font-size: 14px; color: #666;">
                    Default: admin / admin123!
                </p>
            </div>

            <div class="api-info">
                <h3>🚀 API Endpoints</h3>
                <ul>
                    <li><strong>POST</strong> /api/v1/auth/login - User authentication</li>
                    <li><strong>POST</strong> /api/v1/scan - Start security scan</li>
                    <li><strong>GET</strong> /api/v1/scans - List all scans</li>
                    <li><strong>GET</strong> /health - System health check</li>
                    <li><strong>GET</strong> /metrics - Prometheus metrics</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    '''


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


@monitor_scan
def _run_scan(scan_id, scanner):
    """Background function to run scan"""
    try:
        results = scanner.scan()
        active_scans[scan_id]['results'] = results
        active_scans[scan_id]['status'] = 'completed'
        logger.info(f"Scan {scan_id} completed with {len(results)} results")
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['results'] = {'error': str(e)}


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
