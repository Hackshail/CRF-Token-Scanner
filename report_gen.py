import json
import csv
from datetime import datetime
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Production-ready report generator for CSRF vulnerability findings"""

    def __init__(self, results: List[Dict]):
        self.results = results
        self.generation_time = datetime.now().isoformat()

    def generate_json_report(self, filename: str = "report.json") -> str:
        """Generate comprehensive JSON vulnerability report"""
        timestamp = datetime.now().isoformat()

        report = {
            "metadata": {
                "timestamp": timestamp,
                "report_type": "CSRF_Vulnerability_Assessment",
                "total_forms_scanned": len(self.results),
                "generation_date": self.generation_time,
            },
            "summary": self._generate_summary(),
            "findings": self._categorize_by_risk(),
            "detailed_results": self.results,
        }

        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"JSON report generated: {filename}")
        return filename

    def generate_csv_report(self, filename: str = "report.csv") -> str:
        """Generate CSV vulnerability report for spreadsheet analysis"""
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)

            # Write headers
            headers = [
                "Page URL",
                "Form Action",
                "HTTP Method",
                "Status",
                "Risk Level",
                "Risk Score",
                "CSRF Token Present",
                "Timestamp",
            ]
            writer.writerow(headers)

            # Write data rows
            for result in self.results:
                row = [
                    result.get("url", "N/A"),
                    result.get("action", "N/A"),
                    result.get("method", "N/A"),
                    result.get("status", "N/A"),
                    result.get("risk_level", "N/A"),
                    result.get("risk_score", "N/A"),
                    "Yes" if result.get("csrf_token") else "No",
                    result.get("timestamp", "N/A"),
                ]
                writer.writerow(row)

        logger.info(f"CSV report generated: {filename}")
        return filename

    def generate_html_report(self, filename: str = "report.html") -> str:
        """Generate interactive HTML report with statistics"""
        summary = self._generate_summary()
        categorized = self._categorize_by_risk()

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CSRF Vulnerability Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; }}
                h1 {{ color: #333; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
                h2 {{ color: #555; margin-top: 30px; }}
                .summary {{ background-color: #f9f9f9; padding: 15px; border-left: 4px solid #2196F3; margin: 15px 0; }}
                .critical {{ background-color: #ffebee; color: #c62828; padding: 10px; margin: 10px 0; }}
                .high {{ background-color: #fff3e0; color: #e65100; padding: 10px; margin: 10px 0; }}
                .medium {{ background-color: #f3e5f5; color: #6a1b9a; padding: 10px; margin: 10px 0; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #2196F3; color: white; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .metric {{ display: inline-block; background-color: #e3f2fd; padding: 15px; margin: 10px; border-radius: 5px; }}
                .metric-value {{ font-size: 24px; font-weight: bold; color: #1976d2; }}
                .metric-label {{ color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>CSRF Vulnerability Assessment Report</h1>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Executive Summary</h2>
                <div class="summary">
                    <div class="metric">
                        <div class="metric-value">{summary['total_forms']}</div>
                        <div class="metric-label">Forms Analyzed</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value">{summary['vulnerable_forms']}</div>
                        <div class="metric-label">Vulnerable Forms</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" style="color: #c62828;">{summary['critical_findings']}</div>
                        <div class="metric-label">Critical Issues</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" style="color: #e65100;">{summary['high_risk_findings']}</div>
                        <div class="metric-label">High Risk Issues</div>
                    </div>
                </div>
                
                <h2>Critical Vulnerabilities</h2>
                {"".join([self._format_html_result(r, 'critical') for r in categorized.get('critical', [])])}
                
                <h2>High Risk Vulnerabilities</h2>
                {"".join([self._format_html_result(r, 'high') for r in categorized.get('high', [])])}
                
                <h2>Medium Risk Vulnerabilities</h2>
                {"".join([self._format_html_result(r, 'medium') for r in categorized.get('medium', [])])}
                
                <h2>All Findings</h2>
                <table>
                    <tr>
                        <th>URL</th>
                        <th>Method</th>
                        <th>Status</th>
                        <th>Risk Level</th>
                        <th>Token Present</th>
                    </tr>
                    {"".join([f'<tr><td>{r.get("url", "N/A")}</td><td>{r.get("method", "N/A")}</td><td>{r.get("status", "N/A")}</td><td>{r.get("risk_level", "N/A")}</td><td>{"Yes" if r.get("csrf_token") else "No"}</td></tr>' for r in self.results])}
                </table>
                
                <h2>Recommendations</h2>
                <ul>
                    <li><strong>Implement CSRF Tokens:</strong> All state-changing forms should include cryptographically secure CSRF tokens.</li>
                    <li><strong>SameSite Cookies:</strong> Use SameSite=Strict or SameSite=Lax on session cookies.</li>
                    <li><strong>Validate Referer:</strong> Check Referer/Origin headers on sensitive operations.</li>
                    <li><strong>Token Rotation:</strong> Rotate tokens after each request for maximum security.</li>
                    <li><strong>Security Headers:</strong> Implement Content-Security-Policy headers.</li>
                </ul>
            </div>
        </body>
        </html>
        """

        with open(filename, "w") as f:
            f.write(html_content)

        logger.info(f"HTML report generated: {filename}")
        return filename

    def _generate_summary(self) -> Dict:
        """Generate summary statistics"""
        return {
            "total_forms": len(self.results),
            "vulnerable_forms": len(
                [r for r in self.results if r.get("status") != "safe"]
            ),
            "safe_forms": len([r for r in self.results if r.get("status") == "safe"]),
            "critical_findings": len(
                [r for r in self.results if r.get("risk_level") == "critical"]
            ),
            "high_risk_findings": len(
                [r for r in self.results if r.get("risk_level") == "high"]
            ),
            "medium_risk_findings": len(
                [r for r in self.results if r.get("risk_level") == "medium"]
            ),
            "post_forms": len([r for r in self.results if r.get("method") == "POST"]),
            "forms_without_tokens": len(
                [r for r in self.results if not r.get("csrf_token")]
            ),
        }

    def _categorize_by_risk(self) -> Dict[str, List[Dict]]:
        """Categorize findings by risk level"""
        categorized = {"critical": [], "high": [], "medium": [], "low": []}

        for result in self.results:
            risk = result.get("risk_level", "medium")
            if risk in categorized:
                categorized[risk].append(result)

        return categorized

    def _format_html_result(self, result: Dict, risk_level: str) -> str:
        """Format single result for HTML"""
        css_class = risk_level
        return f"""
        <div class="{css_class}">
            <strong>URL:</strong> {result.get('url', 'N/A')}<br>
            <strong>Action:</strong> {result.get('action', 'N/A')}<br>
            <strong>Method:</strong> {result.get('method', 'N/A')}<br>
            <strong>Status:</strong> {result.get('status', 'N/A')}<br>
            <strong>CSRF Token:</strong> {"Present" if result.get('csrf_token') else "Missing"}
        </div>
        """

    def generate_all_reports(self, basename: str = "report") -> Dict[str, str]:
        """Generate all report formats"""
        reports = {
            "json": self.generate_json_report(f"{basename}.json"),
            "csv": self.generate_csv_report(f"{basename}.csv"),
            "html": self.generate_html_report(f"{basename}.html"),
        }
        logger.info(f"All reports generated: {reports}")
        return reports
