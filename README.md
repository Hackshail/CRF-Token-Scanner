# CSRF Scanner - Production Security Assessment Toolkit

A comprehensive, enterprise-grade CSRF (Cross-Site Request Forgery) vulnerability scanner with production-ready features including authentication, monitoring, CI/CD integration, and a web dashboard.

## 🚀 Features

### 🔐 **Authentication & Authorization**
- JWT-based authentication with access/refresh tokens
- Role-based access control (Admin, Security Team, Developer, Auditor)
- Secure password hashing with bcrypt
- Rate limiting and audit logging

### 📊 **Web Dashboard**
- Real-time monitoring dashboard
- Interactive scan management
- Comprehensive reporting and analytics
- System health monitoring

### 🛠️ **Production Features**
- RESTful API with comprehensive endpoints
- Prometheus metrics collection
- Automated alerting system
- Docker containerization ready
- CI/CD pipeline integration

### 🔍 **Advanced Scanning**
- Multi-depth crawling (1-5 levels)
- Comprehensive CSRF detection
- Risk scoring and prioritization
- Form analysis and token validation
- SSL verification options

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │   REST API      │    │   Core Scanner  │
│   (Port 3000)   │◄──►│   (Port 5000)   │◄──►│   Engine        │
│                 │    │                 │    │                 │
│ • Real-time UI  │    │ • JWT Auth      │    │ • Crawling      │
│ • Scan Mgmt     │    │ • Rate Limiting │    │ • CSRF Detection│
│ • Monitoring    │    │ • Async Jobs    │    │ • Risk Scoring  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────┐
                    │   Monitoring    │
                    │   & Alerting    │
                    │                 │
                    │ • Prometheus    │
                    │ • Health Checks │
                    │ • Auto Alerts   │
                    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.13+
- pip package manager

### Installation

1. **Clone and setup:**
```bash
cd "c:\Users\Shailesh\OneDrive\Desktop\my folder"
pip install -r requirements.txt
```

2. **Start production environment:**
```bash
python run_production.py
```

This will start both the API server (port 5000) and dashboard (port 3000).

## 🚀 Deployment

### Render (Recommended)
Deploy easily to Render with one-click deployment:

1. Push your code to GitHub
2. Connect your repository to [Render](https://render.com)
3. Use the provided `render.yaml` configuration
4. Your app will be live at `https://your-app.onrender.com`

See [RENDER_DEPLOYMENT.md](RENDER_DEPLOYMENT.md) for detailed instructions.

### Docker
Build and run with Docker:

```bash
docker build -t csrf-scanner .
docker run -p 5000:5000 csrf-scanner
```

### Access the Dashboard

1. **Open your browser:** http://localhost:3000
2. **Login with default credentials:**
   - Username: `admin`
   - Password: `admin123!`
3. **⚠️ Change the default password immediately in production!**

## 📖 Usage Guide

### 🔐 Authentication

The system uses JWT tokens for authentication:

```bash
# Login to get tokens
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123!"}'

# Use access token for API calls
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:5000/api/v1/scans
```

### 🔍 Starting a Scan

**Via Dashboard:**
1. Navigate to "New Scan" page
2. Enter target URL
3. Configure scan parameters
4. Click "Start Scan"

**Via API:**
```bash
curl -X POST http://localhost:5000/api/v1/scan \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "depth": 2,
    "timeout": 15,
    "max_urls": 100,
    "verify_ssl": true
  }'
```

### 📊 Monitoring

**Dashboard Features:**
- Real-time system health
- Active scan monitoring
- Performance metrics
- Alert management
- Historical data visualization

**API Endpoints:**
- `/health` - System health check
- `/metrics` - Prometheus metrics
- `/alerts` - Active alerts

## 🔧 Configuration

### Environment Variables

```bash
# API Configuration
CSRF_SCANNER_API_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
JWT_EXPIRY_HOURS=24

# Dashboard Configuration
DASHBOARD_PORT=3000
API_BASE_URL=http://localhost:5000

# Database (for production)
USERS_DB_PATH=/path/to/users.json
```

### User Management

**Default Admin User:**
- Username: `admin`
- Password: `admin123!` (⚠️ **CHANGE THIS!**)

**Creating Additional Users:**
```python
from auth_system import create_user, UserRole

create_user("security_team", "secure_password", UserRole.SECURITY_TEAM, "team@company.com")
```

## 🐳 Docker Deployment

### Using Docker Compose

```bash
# Build and start all services
docker-compose up --build

# Or run in background
docker-compose up -d
```

### Services Included:
- **csrf-scanner**: Main application (API + Dashboard)
- **redis**: Rate limiting storage (optional)
- **postgres**: User database (optional)
- **prometheus**: Metrics collection (optional)
- **grafana**: Dashboard visualization (optional)

## 🔄 CI/CD Integration

The project includes GitHub Actions workflows for:

- **Automated Testing:** Python 3.11-3.13 compatibility
- **Security Scanning:** Bandit and Safety vulnerability checks
- **Code Quality:** Black formatting, Flake8 linting, MyPy type checking
- **Deployment:** Automated build and deployment pipelines

### Running CI/CD Locally

```bash
# Install development dependencies
pip install pytest pytest-cov black flake8 mypy bandit safety

# Run tests
pytest --cov=. --cov-report=term-missing

# Code quality checks
black --check .
flake8 .
mypy .

# Security scanning
bandit -r .
safety check
```

## 📈 Monitoring & Alerting

### Built-in Alerts

- **High scan failure rate** (>30%)
- **Memory usage** (>85%)
- **Disk space** (>90%)
- **Rate limit violations** (>10 hits)

### Metrics Collected

- Scan success/failure rates
- Response times
- System resource usage
- API request patterns
- Vulnerability detection statistics

### External Monitoring

The system exposes Prometheus metrics at `/metrics` and provides health checks at `/health`.

## 🔒 Security Considerations

### Production Deployment

1. **Change default credentials immediately**
2. **Use strong JWT secrets**
3. **Enable SSL/TLS encryption**
4. **Configure firewall rules**
5. **Regular security updates**
6. **Monitor logs and alerts**

### Rate Limiting

- Login attempts: 5 per minute
- Scan requests: 10 per hour
- General API: 100 per hour

### SSL Configuration

```python
# In production, configure SSL
app.run(
    host='0.0.0.0',
    port=5000,
    ssl_context=('cert.pem', 'key.pem')
)
```

## 🐛 Troubleshooting

### Common Issues

**API Server Won't Start:**
```bash
# Check for syntax errors
python -m py_compile api_server.py

# Check dependencies
pip install -r requirements.txt
```

**Dashboard Not Loading:**
- Ensure API server is running on port 5000
- Check `API_BASE_URL` environment variable
- Verify JWT token validity

**Scan Failures:**
- Check target URL accessibility
- Verify SSL settings
- Review scan logs

### Logs Location

- Application logs: `logs/` directory
- Scan results: `scan_results/` directory
- User database: `users.json`

## 📚 API Documentation

### Authentication Endpoints

- `POST /api/v1/auth/login` - User authentication
- `POST /api/v1/auth/refresh` - Refresh access token
- `GET /api/v1/auth/me` - Current user info

### Scan Endpoints

- `POST /api/v1/scan` - Start new scan
- `GET /api/v1/scan/{id}` - Get scan status
- `GET /api/v1/scan/{id}/results` - Get scan results
- `DELETE /api/v1/scan/{id}` - Cancel scan
- `GET /api/v1/scans` - List all scans

### Monitoring Endpoints

- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `GET /alerts` - Active alerts

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and quality checks
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse of this software.

---

**Need Help?** Check the troubleshooting section or open an issue on GitHub.

🎯 **Happy Scanning!**
