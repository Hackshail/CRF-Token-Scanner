import re
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class ScanConfig:
    """Configuration for CSRF scanning"""

    def __init__(self):
        self.timeout = 10
        self.max_retries = 3
        self.backoff_factor = 0.5
        self.rate_limit_delay = 0.5
        self.max_urls = 100
        self.skip_external_links = True
        self.verify_ssl = True


class CSRFScanner:
    """Production-ready CSRF vulnerability scanner with advanced detection"""

    def __init__(self, url: str, depth: int = 3, config: Optional[ScanConfig] = None):
        self.url = url
        self.depth = depth
        self.config = config or ScanConfig()

        # Setup resilient session with retries
        self.session = self._create_session()

        self.results = []
        self.visited_urls = set()
        self.forms_found = []
        self.scan_start_time = None

        # Comprehensive CSRF token patterns
        self.csrf_patterns = [
            r'name=["\']?_csrf["\']?',
            r'name=["\']?csrf_token["\']?',
            r'name=["\']?xsrf_token["\']?',
            r'name=["\']?csrf["\']?',
            r'name=["\']?authenticity_token["\']?',
            r'value=["\']?[a-f0-9]{32,}["\']?',
        ]

    def _create_session(self) -> requests.Session:
        """Create a resilient session with retry strategy"""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update(
            {"User-Agent": "Mozilla/5.0 (CSRF Security Scanner by Security Team)"}
        )

        return session

    def scan(self) -> List[Dict]:
        """Execute comprehensive CSRF vulnerability scan"""
        self.scan_start_time = datetime.now()
        logger.info(f"Starting CSRF scan on {self.url} with depth {self.depth}")

        try:
            self._crawl(self.url)
            self._analyze_forms()
            self._check_referer_validation()
            self._test_token_validation()
            self._generate_risk_scores()

            scan_duration = (datetime.now() - self.scan_start_time).total_seconds()
            logger.info(
                f"Scan completed in {scan_duration:.2f}s. Found {len(self.results)} forms"
            )
            return self.results

        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
            return []

    def _crawl(self, url: str, current_depth: int = 0):
        """Crawl URL for forms and links with domain filtering"""
        if current_depth > self.depth or len(self.visited_urls) >= self.config.max_urls:
            return

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)

        try:
            logger.debug(f"Crawling {url} (depth: {current_depth})")
            time.sleep(self.config.rate_limit_delay)

            response = self.session.get(
                url,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=True,
            )
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")
            base_domain = urlparse(url).netloc

            # Find all forms
            forms = soup.find_all("form")
            for form in forms:
                self._process_form(form, url)

            # Follow links for deeper crawling
            if current_depth < self.depth:
                links = soup.find_all("a", href=True)
                for link in links[:10]:
                    next_url = link["href"]

                    if next_url.startswith("#"):
                        continue

                    if not next_url.startswith(("http://", "https://")):
                        next_url = urljoin(url, next_url)

                    next_domain = urlparse(next_url).netloc
                    if self.config.skip_external_links and next_domain != base_domain:
                        continue

                    self._crawl(next_url, current_depth + 1)

        except requests.RequestException as e:
            logger.warning(f"Error crawling {url}: {str(e)}")

    def _process_form(self, form, page_url: str):
        """Extract and analyze form information"""
        action = form.get("action", page_url)
        method = form.get("method", "GET").upper()

        csrf_token = None
        csrf_field_name = None

        inputs = form.find_all("input")
        for inp in inputs:
            inp_name = inp.get("name", "")
            inp_value = inp.get("value", "")

            for pattern in self.csrf_patterns[:-1]:
                if re.search(pattern, inp_name):
                    csrf_token = inp_value
                    csrf_field_name = inp_name
                    break

        form_data = {
            "url": page_url,
            "action": action,
            "method": method,
            "csrf_token": csrf_token,
            "csrf_field_name": csrf_field_name,
            "status": "safe" if csrf_token else "potential_vulnerability",
            "timestamp": datetime.now().isoformat(),
        }

        self.forms_found.append(form_data)
        self.results.append(form_data)
        logger.debug(
            f"Found form: {method} {action} - Token: {'Yes' if csrf_token else 'No'}"
        )

    def _analyze_forms(self):
        """Analyze collected forms for CSRF vulnerabilities"""
        for result in self.results:
            if not result["csrf_token"]:
                result["status"] = "potential_vulnerability"

                if result["method"] in ["POST", "PUT", "DELETE", "PATCH"]:
                    result["risk_level"] = "high"
                else:
                    result["risk_level"] = "medium"

    def _check_referer_validation(self):
        """Check if Referer header is properly validated"""
        malicious_referers = ["https://malicious.com", "https://attacker.com", "null"]

        for result in self.results:
            if result["method"] == "POST" and not result["csrf_token"]:
                for referer in malicious_referers:
                    try:
                        headers = {"Referer": referer}
                        response = self.session.post(
                            result["action"],
                            headers=headers,
                            timeout=self.config.timeout,
                            allow_redirects=False,
                        )

                        if response.status_code not in [403, 401]:
                            result["status"] = "vulnerable_to_referer_bypass"
                            result["risk_level"] = "critical"
                            break
                    except Exception as e:
                        logger.debug(f"Referer check error: {str(e)}")

    def _test_token_validation(self):
        """Test CSRF token validation mechanism"""
        for result in self.results:
            if result["csrf_token"] and result["method"] == "POST":
                try:
                    bad_token = "invalid_token_" + result["csrf_token"][:20]
                    data = {result["csrf_field_name"]: bad_token}

                    response = self.session.post(
                        result["action"],
                        data=data,
                        timeout=self.config.timeout,
                        allow_redirects=False,
                    )

                    if response.status_code == 200:
                        result["status"] = "vulnerable_to_token_replay"
                        result["risk_level"] = "high"
                    elif response.status_code == 403:
                        result["status"] = "safe"
                        result["risk_level"] = "low"

                except Exception as e:
                    logger.debug(f"Token validation test error: {str(e)}")

    def _generate_risk_scores(self):
        """Generate risk scores for each finding"""
        risk_mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        for result in self.results:
            risk = result.get("risk_level", "medium")
            result["risk_score"] = risk_mapping.get(risk, 2)


if __name__ == "__main__":
    try:
        config = ScanConfig()
        config.timeout = 15
        config.max_urls = 50

        scanner = CSRFScanner("https://example.com", depth=2, config=config)
        results = scanner.scan()

        print(f"\nFound {len(results)} forms during scan")
        for result in results:
            print(
                f"  {result['method']} {result['action']} - Status: {result['status']}"
            )

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Application error: {str(e)}", exc_info=True)
