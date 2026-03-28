"""
Monitoring and Alerting System for CSRF Scanner
Features: Prometheus metrics, health checks, alerting, performance monitoring
"""

import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import json
import os
from flask import Flask
import psutil
import threading

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status"""
    ACTIVE = "active"
    RESOLVED = "resolved"


@dataclass
class Alert:
    """Alert data structure"""
    id: str
    name: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    created_at: datetime
    resolved_at: Optional[datetime] = None
    labels: Dict[str, str] = None

    def __post_init__(self):
        if self.labels is None:
            self.labels = {}


class MetricsCollector:
    """Collects and exposes Prometheus-style metrics"""

    def __init__(self):
        self.metrics = {}
        self.start_time = time.time()

    def increment_counter(self, name: str, value: float = 1.0, labels: Dict[str, str] = None):
        """Increment a counter metric"""
        if name not in self.metrics:
            self.metrics[name] = {'type': 'counter', 'value': 0.0, 'labels': {}}

        self.metrics[name]['value'] += value
        if labels:
            self.metrics[name]['labels'].update(labels)

    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric"""
        self.metrics[name] = {
            'type': 'gauge',
            'value': value,
            'labels': labels or {}
        }

    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Observe a histogram metric"""
        if name not in self.metrics:
            self.metrics[name] = {
                'type': 'histogram',
                'observations': [],
                'labels': {}
            }

        self.metrics[name]['observations'].append({
            'value': value,
            'timestamp': time.time(),
            'labels': labels or {}
        })

        # Keep only last 1000 observations
        if len(self.metrics[name]['observations']) > 1000:
            self.metrics[name]['observations'] = self.metrics[name]['observations'][-1000:]

    def get_metrics_text(self) -> str:
        """Export metrics in Prometheus format"""
        lines = []

        for name, metric in self.metrics.items():
            if metric['type'] == 'counter':
                lines.append(f'# TYPE {name} counter')
                lines.append(f'{name} {metric["value"]}')

            elif metric['type'] == 'gauge':
                lines.append(f'# TYPE {name} gauge')
                lines.append(f'{name} {metric["value"]}')

            elif metric['type'] == 'histogram':
                lines.append(f'# TYPE {name} histogram')
                count = len(metric['observations'])
                sum_val = sum(obs['value'] for obs in metric['observations'])
                lines.append(f'{name}_count {count}')
                lines.append(f'{name}_sum {sum_val}')

        return '\n'.join(lines)


class AlertManager:
    """Manages alerts and notifications"""

    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.alert_rules = self._load_alert_rules()

    def _load_alert_rules(self) -> Dict[str, Dict]:
        """Load alert rules from configuration"""
        return {
            'high_scan_failure_rate': {
                'condition': lambda metrics: self._check_scan_failure_rate(metrics),
                'severity': AlertSeverity.WARNING,
                'description': 'High scan failure rate detected'
            },
            'memory_usage_high': {
                'condition': lambda metrics: self._check_memory_usage(),
                'severity': AlertSeverity.WARNING,
                'description': 'High memory usage detected'
            },
            'disk_space_low': {
                'condition': lambda metrics: self._check_disk_space(),
                'severity': AlertSeverity.ERROR,
                'description': 'Low disk space available'
            },
            'api_rate_limit_exceeded': {
                'condition': lambda metrics: self._check_rate_limits(metrics),
                'severity': AlertSeverity.WARNING,
                'description': 'API rate limits frequently exceeded'
            }
        }

    def create_alert(self, name: str, description: str, severity: AlertSeverity,
                    labels: Dict[str, str] = None) -> Alert:
        """Create a new alert"""
        alert_id = f"{name}_{int(time.time())}"
        alert = Alert(
            id=alert_id,
            name=name,
            description=description,
            severity=severity,
            status=AlertStatus.ACTIVE,
            created_at=datetime.utcnow(),
            labels=labels or {}
        )

        self.alerts[alert_id] = alert
        logger.warning(f"ALERT CREATED: {name} - {description}")
        self._send_notification(alert)

        return alert

    def resolve_alert(self, alert_id: str):
        """Resolve an active alert"""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow()
            logger.info(f"ALERT RESOLVED: {alert.name}")
            self._send_notification(alert)

    def check_alerts(self, metrics_collector: MetricsCollector):
        """Check all alert rules and create alerts if conditions are met"""
        for rule_name, rule in self.alert_rules.items():
            try:
                if rule['condition'](metrics_collector):
                    # Check if alert already exists
                    active_alerts = [a for a in self.alerts.values()
                                   if a.name == rule_name and a.status == AlertStatus.ACTIVE]

                    if not active_alerts:
                        self.create_alert(
                            name=rule_name,
                            description=rule['description'],
                            severity=rule['severity']
                        )
            except Exception as e:
                logger.error(f"Error checking alert rule {rule_name}: {e}")

    def _check_scan_failure_rate(self, metrics: MetricsCollector) -> bool:
        """Check if scan failure rate is too high"""
        failed_scans = metrics.metrics.get('csrf_scans_failed_total', {}).get('value', 0)
        total_scans = metrics.metrics.get('csrf_scans_total', {}).get('value', 0)

        if total_scans > 10:  # Only check after minimum scans
            failure_rate = failed_scans / total_scans
            return failure_rate > 0.3  # 30% failure rate threshold

        return False

    def _check_memory_usage(self) -> bool:
        """Check system memory usage"""
        memory = psutil.virtual_memory()
        return memory.percent > 85  # 85% memory usage threshold

    def _check_disk_space(self) -> bool:
        """Check available disk space"""
        disk = psutil.disk_usage('/')
        return disk.percent > 90  # 90% disk usage threshold

    def _check_rate_limits(self, metrics: MetricsCollector) -> bool:
        """Check if rate limits are frequently exceeded"""
        rate_limit_hits = metrics.metrics.get('rate_limit_exceeded_total', {}).get('value', 0)
        return rate_limit_hits > 10  # More than 10 rate limit hits

    def _send_notification(self, alert: Alert):
        """Send alert notification (email, Slack, etc.)"""
        # In production, integrate with notification services
        notification = {
            'alert_id': alert.id,
            'name': alert.name,
            'description': alert.description,
            'severity': alert.severity.value,
            'status': alert.status.value,
            'timestamp': alert.created_at.isoformat(),
            'labels': alert.labels
        }

        # Log notification
        logger.info(f"NOTIFICATION: {json.dumps(notification)}")

        # TODO: Send to Slack, email, PagerDuty, etc.
        # Example: send_slack_notification(notification)
        # Example: send_email_notification(notification)

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        return [alert for alert in self.alerts.values() if alert.status == AlertStatus.ACTIVE]


class HealthChecker:
    """System health checker"""

    def __init__(self):
        self.last_health_check = None
        self.health_status = {}

    def perform_health_check(self) -> Dict:
        """Perform comprehensive health check"""
        health = {
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'healthy',
            'checks': {}
        }

        # System resources
        health['checks']['memory'] = self._check_memory()
        health['checks']['disk'] = self._check_disk()
        health['checks']['cpu'] = self._check_cpu()

        # Application specific
        health['checks']['api_server'] = self._check_api_server()
        health['checks']['database'] = self._check_database()

        # Overall status
        failed_checks = [k for k, v in health['checks'].items() if not v.get('healthy', False)]
        if failed_checks:
            health['status'] = 'unhealthy'
            health['failed_checks'] = failed_checks

        self.last_health_check = health
        return health

    def _check_memory(self) -> Dict:
        memory = psutil.virtual_memory()
        return {
            'healthy': memory.percent < 90,
            'usage_percent': memory.percent,
            'available_mb': memory.available / 1024 / 1024
        }

    def _check_disk(self) -> Dict:
        disk = psutil.disk_usage('/')
        return {
            'healthy': disk.percent < 95,
            'usage_percent': disk.percent,
            'free_gb': disk.free / 1024 / 1024 / 1024
        }

    def _check_cpu(self) -> Dict:
        cpu_percent = psutil.cpu_percent(interval=1)
        return {
            'healthy': cpu_percent < 95,
            'usage_percent': cpu_percent
        }

    def _check_api_server(self) -> Dict:
        # Check if API server is responding
        try:
            import requests
            response = requests.get('http://localhost:5000/health', timeout=5)
            return {
                'healthy': response.status_code == 200,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e)
            }

    def _check_database(self) -> Dict:
        # Check database connectivity
        try:
            # For now, just check if users.json exists and is readable
            users_file = os.getenv('USERS_DB_PATH', 'users.json')
            if os.path.exists(users_file):
                with open(users_file, 'r') as f:
                    json.load(f)
                return {'healthy': True}
            else:
                return {'healthy': False, 'error': 'Users database not found'}
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e)
            }


# Global instances
metrics_collector = MetricsCollector()
alert_manager = AlertManager()
health_checker = HealthChecker()


def init_monitoring(app: Flask):
    """Initialize monitoring for Flask app"""

    @app.route('/metrics')
    def metrics():
        """Prometheus metrics endpoint"""
        return metrics_collector.get_metrics_text(), 200, {'Content-Type': 'text/plain'}

    @app.route('/health')
    def health():
        """Health check endpoint"""
        health_data = health_checker.perform_health_check()
        status_code = 200 if health_data['status'] == 'healthy' else 503
        return jsonify(health_data), status_code

    @app.route('/alerts')
    def alerts():
        """Active alerts endpoint"""
        active_alerts = alert_manager.get_active_alerts()
        return jsonify({
            'alerts': [
                {
                    'id': alert.id,
                    'name': alert.name,
                    'description': alert.description,
                    'severity': alert.severity.value,
                    'created_at': alert.created_at.isoformat(),
                    'labels': alert.labels
                } for alert in active_alerts
            ],
            'total': len(active_alerts)
        }), 200

    # Start background monitoring thread
    def background_monitoring():
        while True:
            try:
                # Update system metrics
                memory = psutil.virtual_memory()
                metrics_collector.set_gauge('system_memory_usage_percent', memory.percent)
                metrics_collector.set_gauge('system_memory_available_mb',
                                          memory.available / 1024 / 1024)

                disk = psutil.disk_usage('/')
                metrics_collector.set_gauge('system_disk_usage_percent', disk.percent)
                metrics_collector.set_gauge('system_disk_free_gb',
                                          disk.free / 1024 / 1024 / 1024)

                cpu = psutil.cpu_percent()
                metrics_collector.set_gauge('system_cpu_usage_percent', cpu)

                # Check alerts
                alert_manager.check_alerts(metrics_collector)

                time.sleep(60)  # Check every minute

            except Exception as e:
                logger.error(f"Error in background monitoring: {e}")
                time.sleep(60)

    monitoring_thread = threading.Thread(target=background_monitoring, daemon=True)
    monitoring_thread.start()


# Monitoring decorators
def monitor_scan(func):
    """Decorator to monitor scan operations"""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time

            metrics_collector.increment_counter('csrf_scans_total')
            metrics_collector.observe_histogram('csrf_scan_duration_seconds', duration)

            if hasattr(result, '__len__') and len(result) > 0:
                metrics_collector.increment_counter('csrf_vulnerabilities_found_total',
                                                 value=len([r for r in result if r.get('status') != 'safe']))

            return result

        except Exception as e:
            metrics_collector.increment_counter('csrf_scans_failed_total')
            raise e

    return wrapper


def monitor_api_request(endpoint: str):
    """Decorator to monitor API requests"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                metrics_collector.increment_counter(f'api_requests_total',
                                                 labels={'endpoint': endpoint, 'status': 'success'})
                metrics_collector.observe_histogram(f'api_request_duration_seconds',
                                                 duration, labels={'endpoint': endpoint})

                return result

            except Exception as e:
                metrics_collector.increment_counter(f'api_requests_total',
                                                 labels={'endpoint': endpoint, 'status': 'error'})
                raise e

        return wrapper
    return decorator