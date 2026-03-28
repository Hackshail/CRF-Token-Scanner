"""
CSRF Scanner Dashboard - Web Interface
Production-ready dashboard for monitoring and managing CSRF scans
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import requests
import json
import os
from datetime import datetime, timedelta
from functools import wraps
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('DASHBOARD_SECRET_KEY', 'change-this-in-production-dashboard')

# API Configuration
API_BASE_URL = os.getenv('API_BASE_URL', 'http://localhost:5000')
DASHBOARD_PORT = int(os.getenv('DASHBOARD_PORT', '3000'))

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)


def login_required(f):
    """Decorator to require login for dashboard access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def api_request(method, endpoint, data=None, headers=None):
    """Make authenticated API request"""
    url = f"{API_BASE_URL}{endpoint}"
    default_headers = {}

    if 'access_token' in session:
        default_headers['Authorization'] = f"Bearer {session['access_token']}"

    if headers:
        default_headers.update(headers)

    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=default_headers)
        elif method.upper() == 'POST':
            response = requests.post(url, json=data, headers=default_headers)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=default_headers)
        else:
            return None

        return response
    except Exception as e:
        logger.error(f"API request failed: {e}")
        return None


@app.route('/')
def index():
    """Dashboard home page"""
    if 'access_token' not in session:
        return redirect(url_for('login'))

    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password required', 'error')
            return render_template('login.html')

        # Authenticate with API
        response = api_request('POST', '/api/v1/auth/login', {
            'username': username,
            'password': password
        })

        if response and response.status_code == 200:
            data = response.json()
            session['access_token'] = data['access_token']
            session['refresh_token'] = data['refresh_token']
            session['user'] = data['user']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html', user=session.get('user'))


@app.route('/api/dashboard/stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Get health status
        health_response = api_request('GET', '/health')
        health_data = health_response.json() if health_response else {'status': 'unknown'}

        # Get active scans
        scans_response = api_request('GET', '/api/v1/scans')
        scans_data = scans_response.json() if scans_response else {'scans': []}

        # Get metrics
        metrics_response = api_request('GET', '/metrics')
        metrics_text = metrics_response.text if metrics_response else ""

        # Parse metrics
        metrics = parse_prometheus_metrics(metrics_text)

        # Get alerts
        alerts_response = api_request('GET', '/alerts')
        alerts_data = alerts_response.json() if alerts_response else {'alerts': []}

        stats = {
            'health': health_data,
            'active_scans': len([s for s in scans_data.get('scans', []) if s['status'] == 'running']),
            'total_scans': scans_data.get('total', 0),
            'completed_scans': len([s for s in scans_data.get('scans', []) if s['status'] == 'completed']),
            'failed_scans': len([s for s in scans_data.get('scans', []) if s['status'] == 'failed']),
            'metrics': metrics,
            'alerts': alerts_data.get('alerts', []),
            'timestamp': datetime.now().isoformat()
        }

        return jsonify(stats)

    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': 'Failed to load dashboard data'}), 500


@app.route('/scans')
@login_required
def scans_page():
    """Scans management page"""
    return render_template('scans.html', user=session.get('user'))


@app.route('/api/scans')
@login_required
def get_scans():
    """Get all scans"""
    response = api_request('GET', '/api/v1/scans')
    if response:
        return jsonify(response.json())
    return jsonify({'scans': [], 'error': 'Failed to load scans'})


@app.route('/scan/new', methods=['GET', 'POST'])
@login_required
def new_scan():
    """Create new scan"""
    if request.method == 'POST':
        url = request.form.get('url')
        depth = request.form.get('depth', 2)
        timeout = request.form.get('timeout', 15)
        max_urls = request.form.get('max_urls', 100)
        verify_ssl = request.form.get('verify_ssl') == 'on'

        if not url:
            flash('URL is required', 'error')
            return render_template('new_scan.html')

        scan_data = {
            'url': url,
            'depth': int(depth),
            'timeout': int(timeout),
            'max_urls': int(max_urls),
            'verify_ssl': verify_ssl
        }

        response = api_request('POST', '/api/v1/scan', scan_data)

        if response and response.status_code == 202:
            scan_id = response.json()['scan_id']
            flash(f'Scan started successfully! ID: {scan_id}', 'success')
            return redirect(url_for('scan_detail', scan_id=scan_id))
        else:
            flash('Failed to start scan', 'error')

    return render_template('new_scan.html', user=session.get('user'))


@app.route('/scan/<scan_id>')
@login_required
def scan_detail(scan_id):
    """Scan detail page"""
    return render_template('scan_detail.html', scan_id=scan_id, user=session.get('user'))


@app.route('/api/scan/<scan_id>')
@login_required
def get_scan_detail(scan_id):
    """Get scan details"""
    response = api_request('GET', f'/api/v1/scan/{scan_id}')
    if response:
        return jsonify(response.json())
    return jsonify({'error': 'Failed to load scan details'})


@app.route('/api/scan/<scan_id>/results')
@login_required
def get_scan_results(scan_id):
    """Get scan results"""
    response = api_request('GET', f'/api/v1/scan/{scan_id}/results')
    if response:
        return jsonify(response.json())
    return jsonify({'error': 'Failed to load scan results'})


@app.route('/api/scan/<scan_id>/cancel', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    """Cancel a scan"""
    response = api_request('DELETE', f'/api/v1/scan/{scan_id}')
    if response and response.status_code == 200:
        return jsonify({'success': True, 'message': 'Scan cancelled'})
    return jsonify({'success': False, 'error': 'Failed to cancel scan'})


@app.route('/monitoring')
@login_required
def monitoring():
    """Monitoring dashboard"""
    return render_template('monitoring.html', user=session.get('user'))


@app.route('/api/monitoring/metrics')
@login_required
def get_metrics():
    """Get monitoring metrics"""
    response = api_request('GET', '/metrics')
    if response:
        return response.text, 200, {'Content-Type': 'text/plain'}
    return 'Metrics unavailable', 500


@app.route('/api/monitoring/health')
@login_required
def get_health():
    """Get health status"""
    response = api_request('GET', '/health')
    if response:
        return jsonify(response.json())
    return jsonify({'status': 'unknown'})


@app.route('/api/monitoring/alerts')
@login_required
def get_alerts():
    """Get active alerts"""
    response = api_request('GET', '/alerts')
    if response:
        return jsonify(response.json())
    return jsonify({'alerts': []})


def parse_prometheus_metrics(metrics_text):
    """Parse Prometheus metrics text into structured data"""
    metrics = {}
    lines = metrics_text.split('\n')

    for line in lines:
        line = line.strip()
        if line.startswith('#') or not line:
            continue

        if '{' in line and '}' in line:
            # Handle labeled metrics
            metric_name = line.split('{')[0]
            value = line.split('} ')[-1]
        else:
            parts = line.split(' ')
            if len(parts) >= 2:
                metric_name = parts[0]
                value = parts[1]
            else:
                continue

        try:
            # Convert value to appropriate type
            if '.' in value:
                metrics[metric_name] = float(value)
            else:
                metrics[metric_name] = int(value)
        except ValueError:
            metrics[metric_name] = value

    return metrics


@app.context_processor
def inject_now():
    """Inject current datetime into templates"""
    return {'now': datetime.now()}


if __name__ == '__main__':
    print("Starting CSRF Scanner Dashboard...")
    print(f"API URL: {API_BASE_URL}")
    print(f"Dashboard URL: http://localhost:{DASHBOARD_PORT}")
    print("Login with: admin / admin123!")
    print("[WARNING] Remember to change default password in production!")

    app.run(
        debug=True,
        host='0.0.0.0',
        port=DASHBOARD_PORT,
        threaded=True
    )