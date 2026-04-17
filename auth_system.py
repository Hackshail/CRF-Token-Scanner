"""
Production-Ready Authentication System for CSRF Scanner API
Features: JWT tokens, rate limiting, role-based access, audit logging
"""

import os
import jwt
import bcrypt
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from typing import Dict, Optional, List
import json
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class UserRole(Enum):
    """User roles for access control"""

    ADMIN = "admin"
    SECURITY_TEAM = "security_team"
    DEVELOPER = "developer"
    AUDITOR = "auditor"


@dataclass
class User:
    """User data structure"""

    id: str
    username: str
    role: UserRole
    email: str
    active: bool = True
    created_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()


class AuthConfig:
    """Authentication configuration"""

    def __init__(self):
        self.jwt_secret = os.getenv(
            "JWT_SECRET_KEY", "change-this-in-production-very-long-random-string"
        )
        self.jwt_algorithm = "HS256"
        self.token_expiry_hours = int(os.getenv("JWT_EXPIRY_HOURS", "24"))
        self.refresh_token_expiry_days = int(
            os.getenv("REFRESH_TOKEN_EXPIRY_DAYS", "30")
        )
        self.bcrypt_rounds = 12

        # Rate limiting
        self.rate_limits = {
            "login": "5 per minute",
            "scan_request": "10 per hour",
            "api_general": "100 per hour",
        }


class AuthManager:
    """Production authentication manager"""

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self.users_db = self._load_users()
        self.audit_log = []

    def _load_users(self) -> Dict[str, User]:
        """Load users from secure storage (in production, use database)"""
        # In production, replace with database queries
        users_file = os.getenv("USERS_DB_PATH", "users.json")

        if os.path.exists(users_file):
            try:
                with open(users_file, "r") as f:
                    users_data = json.load(f)
                    users = {}
                    for username, data in users_data.items():
                        users[username] = User(
                            id=data["id"],
                            username=username,
                            role=UserRole(data["role"]),
                            email=data["email"],
                            active=data.get("active", True),
                            created_at=datetime.fromisoformat(data["created_at"]),
                        )
                    return users
            except Exception as e:
                logger.error(f"Failed to load users: {e}")

        # Default admin user (CHANGE THIS IN PRODUCTION!)
        default_admin = User(
            id="admin-001",
            username="admin",
            role=UserRole.ADMIN,
            email="admin@company.com",
        )

        # Hash default password: "admin123!" (CHANGE THIS!)
        default_admin.hashed_password = bcrypt.hashpw(
            "admin123!".encode(), bcrypt.gensalt(self.config.bcrypt_rounds)
        ).decode()

        return {"admin": default_admin}

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user credentials"""
        user = self.users_db.get(username)
        if not user or not user.active:
            return None

        # Check password (in production, get from database)
        stored_hash = getattr(user, "hashed_password", None)
        if not stored_hash:
            return None

        if bcrypt.checkpw(password.encode(), stored_hash.encode()):
            self._audit_log(
                "login_success", username, request.remote_addr if request else "unknown"
            )
            return user

        self._audit_log(
            "login_failed", username, request.remote_addr if request else "unknown"
        )
        return None

    def generate_tokens(self, user: User) -> Dict[str, str]:
        """Generate JWT access and refresh tokens"""
        now = datetime.utcnow()

        # Access token
        access_payload = {
            "user_id": user.id,
            "username": user.username,
            "role": user.role.value,
            "email": user.email,
            "exp": now + timedelta(hours=self.config.token_expiry_hours),
            "iat": now,
            "iss": "csrf-scanner-api",
        }

        # Refresh token
        refresh_payload = {
            "user_id": user.id,
            "username": user.username,
            "exp": now + timedelta(days=self.config.refresh_token_expiry_days),
            "iat": now,
            "type": "refresh",
        }

        access_token = jwt.encode(
            access_payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm
        )
        refresh_token = jwt.encode(
            refresh_payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self.config.token_expiry_hours * 3600,
        }

    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token, self.config.jwt_secret, algorithms=[self.config.jwt_algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Generate new access token using refresh token"""
        payload = self.verify_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            return None

        user = self.users_db.get(payload["username"])
        if not user or not user.active:
            return None

        # Generate new access token
        now = datetime.utcnow()
        access_payload = {
            "user_id": user.id,
            "username": user.username,
            "role": user.role.value,
            "email": user.email,
            "exp": now + timedelta(hours=self.config.token_expiry_hours),
            "iat": now,
            "iss": "csrf-scanner-api",
        }

        access_token = jwt.encode(
            access_payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.token_expiry_hours * 3600,
        }

    def _audit_log(self, action: str, username: str, ip_address: str):
        """Log authentication events"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "username": username,
            "ip_address": ip_address,
            "user_agent": (
                request.headers.get("User-Agent", "unknown") if request else "unknown"
            ),
        }
        self.audit_log.append(log_entry)
        logger.info(f"AUDIT: {action} - {username} from {ip_address}")


# Global auth manager instance
auth_manager = AuthManager()


def require_auth(roles: Optional[List[UserRole]] = None):
    """Decorator for JWT authentication and authorization"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")

            if not auth_header.startswith("Bearer "):
                return (
                    jsonify({"error": "Missing or invalid authorization header"}),
                    401,
                )

            token = auth_header.split(" ")[1]
            payload = auth_manager.verify_token(token)

            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401

            # Check role authorization
            if roles:
                user_role = UserRole(payload.get("role"))
                if user_role not in roles:
                    return jsonify({"error": "Insufficient permissions"}), 403

            # Store user info in request context
            g.user = {
                "id": payload["user_id"],
                "username": payload["username"],
                "role": payload["role"],
                "email": payload["email"],
            }

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def create_rate_limiter(app):
    """Create rate limiter for the Flask app"""
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
    )

    # Specific rate limits for different endpoints
    limiter.limit("5 per minute")(login_endpoint)
    limiter.limit("10 per hour")(scan_request_endpoint)
    limiter.limit("100 per hour")(general_api_endpoint)

    return limiter


# Placeholder functions for rate limiting decorators
def login_endpoint():
    pass


def scan_request_endpoint():
    pass


def general_api_endpoint():
    pass


# Production user management functions
def create_user(username: str, password: str, role: UserRole, email: str) -> bool:
    """Create a new user (admin only)"""
    if username in auth_manager.users_db:
        return False

    hashed_password = bcrypt.hashpw(
        password.encode(), bcrypt.gensalt(auth_manager.config.bcrypt_rounds)
    )

    user = User(
        id=f"user-{len(auth_manager.users_db) + 1}",
        username=username,
        role=role,
        email=email,
    )
    user.hashed_password = hashed_password.decode()

    auth_manager.users_db[username] = user
    auth_manager._save_users()
    logger.info(f"User created: {username}")
    return True


def auth_manager_save_users(auth_manager):
    """Save users to secure storage"""
    users_data = {}
    for username, user in auth_manager.users_db.items():
        users_data[username] = {
            "id": user.id,
            "role": user.role.value,
            "email": user.email,
            "active": user.active,
            "created_at": user.created_at.isoformat(),
        }

    users_file = os.getenv("USERS_DB_PATH", "users.json")
    try:
        with open(users_file, "w") as f:
            json.dump(users_data, f, indent=2)
        logger.info("Users database saved")
    except Exception as e:
        logger.error(f"Failed to save users: {e}")


# Add save method to AuthManager
AuthManager._save_users = auth_manager_save_users
