import json
from pathlib import Path
from base_ import ScanConfig
from report_gen import ReportGenerator
from main import create_parser


def test_scan_config_defaults():
    config = ScanConfig()
    assert config.timeout == 10
    assert config.max_urls == 100
    assert config.verify_ssl is True
    assert config.skip_external_links is True


def test_report_generator_file_outputs(tmp_path):
    results = [
        {
            "url": "http://example.com",
            "action": "/submit",
            "method": "POST",
            "status": "potential_vulnerability",
            "risk_level": "high",
            "risk_score": 3,
            "csrf_token": None,
            "timestamp": "2026-01-01T00:00:00",
        }
    ]

    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report = ReportGenerator(results)

    json_file = report_dir / "report.json"
    csv_file = report_dir / "report.csv"
    html_file = report_dir / "report.html"

    assert report.generate_json_report(str(json_file)) == str(json_file)
    assert report.generate_csv_report(str(csv_file)) == str(csv_file)
    assert report.generate_html_report(str(html_file)) == str(html_file)

    assert json_file.exists()
    assert csv_file.exists()
    assert html_file.exists()

    loaded = json.loads(json_file.read_text())
    assert loaded["metadata"]["report_type"] == "CSRF_Vulnerability_Assessment"
    assert loaded["summary"]["total_forms"] == 1


def test_main_parser_has_url_option():
    parser = create_parser()
    args = parser.parse_args(["-u", "https://example.com"])
    assert args.url == "https://example.com"
    assert args.depth == 2
    assert args.report == "all"
