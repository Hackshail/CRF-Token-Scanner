"""
Configuration presets for different scanning scenarios
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanProfile:
    """Predefined scan profile configuration"""
    name: str
    description: str
    timeout: int
    max_retries: int
    rate_limit_delay: float
    max_urls: int
    depth: int
    skip_external_links: bool
    verify_ssl: bool


# Pre-configured profiles for different scenarios

LIGHT_SCAN = ScanProfile(
    name="Light Scan",
    description="Quick assessment, minimal resource usage",
    timeout=5,
    max_retries=1,
    rate_limit_delay=0.2,
    max_urls=20,
    depth=1,
    skip_external_links=True,
    verify_ssl=True
)

STANDARD_SCAN = ScanProfile(
    name="Standard Scan",
    description="Balanced security assessment (recommended)",
    timeout=10,
    max_retries=3,
    rate_limit_delay=0.5,
    max_urls=100,
    depth=2,
    skip_external_links=True,
    verify_ssl=True
)

DEEP_SCAN = ScanProfile(
    name="Deep Scan",
    description="Comprehensive security assessment",
    timeout=15,
    max_retries=5,
    rate_limit_delay=1.0,
    max_urls=500,
    depth=4,
    skip_external_links=False,
    verify_ssl=True
)

AGGRESSIVE_SCAN = ScanProfile(
    name="Aggressive Scan",
    description="Maximum coverage assessment (high resource usage)",
    timeout=20,
    max_retries=5,
    rate_limit_delay=0.2,
    max_urls=1000,
    depth=5,
    skip_external_links=False,
    verify_ssl=True
)

INTERNAL_SCAN = ScanProfile(
    name="Internal Scan",
    description="Internal network assessment (can skip SSL verification)",
    timeout=10,
    max_retries=3,
    rate_limit_delay=0.3,
    max_urls=200,
    depth=3,
    skip_external_links=True,
    verify_ssl=False
)


# Usage examples:
# 
#   from config import STANDARD_SCAN, ScanProfile
#   from src.base_ import CSRFScanner, ScanConfig
#   
#   # Using predefined profile
#   config = ScanConfig()
#   config.timeout = STANDARD_SCAN.timeout
#   config.max_urls = STANDARD_SCAN.max_urls
#   scanner = CSRFScanner(url, STANDARD_SCAN.depth, config)
#   
#   # Or create custom profile
#   custom = ScanProfile(
#       name="Custom",
#       description="My custom configuration",
#       timeout=8,
#       max_retries=2,
#       rate_limit_delay=0.5,
#       max_urls=50,
#       depth=2,
#       skip_external_links=True,
#       verify_ssl=True
#   )


# Risk thresholds for automated alerting
RISK_THRESHOLDS = {
    'critical': 1,        # Alert if >= 1 critical finding
    'high': 3,            # Alert if >= 3 high-risk findings
    'medium': 5,          # Alert if >= 5 medium-risk findings
    'unprotected_post': 2  # Alert if >= 2 POST forms without CSRF protection
}


# Email alert configuration (if using notification system)
ALERT_CONFIG = {
    'enabled': False,
    'smtp_server': 'smtp.example.com',
    'smtp_port': 587,
    'sender_email': 'security@example.com',
    'recipient_emails': ['security-team@example.com'],
    'subject_prefix': '[CSRF Scan Alert]'
}


# Slack webhook for real-time notifications (if using Slack integration)
SLACK_CONFIG = {
    'enabled': False,
    'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/HERE',
    'channel': '#security-alerts',
    'mention_on_critical': '@security-team'
}


# API Configuration
API_CONFIG = {
    'port': 5000,
    'host': '0.0.0.0',
    'debug': False,
    'cors_origins': ['localhost', '127.0.0.1'],
    'api_key_header': 'X-API-Key',
    'max_scan_duration': 3600  # 1 hour
}


# Logging configuration
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'csrf_scanner.log',
    'max_file_size': 10 * 1024 * 1024,  # 10 MB
    'backup_count': 5
}


# Database configuration (if using persistence)
DATABASE_CONFIG = {
    'enabled': False,
    'type': 'sqlite',  # or 'postgresql', 'mysql'
    'host': 'localhost',
    'port': 5432,
    'name': 'csrf_scanner',
    'user': 'scanner_user',
    'password': 'secure_password',
    'table_prefix': 'csrf_'
}


def get_profile_by_name(name: str) -> Optional[ScanProfile]:
    """Get predefined profile by name"""
    profiles = {
        'light': LIGHT_SCAN,
        'standard': STANDARD_SCAN,
        'deep': DEEP_SCAN,
        'aggressive': AGGRESSIVE_SCAN,
        'internal': INTERNAL_SCAN
    }
    return profiles.get(name.lower())


def list_profiles():
    """List all available profiles"""
    profiles = [
        LIGHT_SCAN,
        STANDARD_SCAN,
        DEEP_SCAN,
        AGGRESSIVE_SCAN,
        INTERNAL_SCAN
    ]
    
    print("\nAvailable Scan Profiles:")
    print("-" * 60)
    for profile in profiles:
        print(f"\n{profile.name}")
        print(f"  Description: {profile.description}")
        print(f"  Timeout: {profile.timeout}s | Max URLs: {profile.max_urls} | Depth: {profile.depth}")
    print()


if __name__ == '__main__':
    list_profiles()
