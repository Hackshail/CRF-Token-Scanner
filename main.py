#!/usr/bin/env python3
"""
CSRF Vulnerability Scanner - Main Application
Production-ready entry point for comprehensive CSRF security assessments
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(
            f'csrf_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        ),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def create_parser():
    """Create command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="CSRF Vulnerability Scanner - Comprehensive web form security assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single URL with depth 2
  python main.py -u https://example.com -d 2
  
  # Scan and generate all report formats
  python main.py -u https://example.com -r all -f myreport
  
  # Run with custom configuration
  python main.py -u https://example.com --timeout 20 --max-urls 200
  
  # Start API server
  python main.py --api
        """,
    )

    # Scanning options
    parser.add_argument("-u", "--url", type=str, help="Target URL to scan")
    parser.add_argument(
        "-d", "--depth", type=int, default=2, help="Crawl depth (default: 2)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--max-urls", type=int, default=100, help="Maximum URLs to crawl"
    )

    # Reporting options
    parser.add_argument(
        "-r",
        "--report",
        choices=["json", "csv", "html", "all"],
        default="all",
        help="Report format(s) to generate",
    )
    parser.add_argument(
        "-f",
        "--filename",
        type=str,
        default="csrf_report",
        help="Base filename for reports",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        default="reports",
        help="Output directory for reports",
    )

    # Server options
    parser.add_argument("--api", action="store_true", help="Start REST API server")
    parser.add_argument("--api-port", type=int, default=5000, help="API server port")

    # Configuration
    parser.add_argument("--skip-ssl", action="store_true", help="Skip SSL verification")
    parser.add_argument(
        "--no-external", action="store_true", help="Don't follow external links"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    return parser


def scan_target(url, depth, config_opts):
    """Execute CSRF scan on target"""
    try:
        from base_ import CSRFScanner, ScanConfig

        # Create config
        config = ScanConfig()
        config.timeout = config_opts.get("timeout", 10)
        config.max_urls = config_opts.get("max_urls", 100)
        config.verify_ssl = not config_opts.get("skip_ssl", False)
        config.skip_external_links = config_opts.get("no_external", False)

        # Run scanner
        logger.info(f"Starting CSRF scan on {url}")
        scanner = CSRFScanner(url, depth=depth, config=config)
        results = scanner.scan()

        logger.info(f"Scan completed. Found {len(results)} forms")
        return results

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        return None


def generate_reports(results, report_type, filename, output_dir):
    """Generate reports in specified formats"""
    try:
        from report_gen import ReportGenerator

        # Create output directory
        Path(output_dir).mkdir(exist_ok=True)

        if results is None:
            logger.error("No results to report")
            return False

        generator = ReportGenerator(results)

        reports_generated = []

        if report_type in ["json", "all"]:
            json_file = Path(output_dir) / f"{filename}.json"
            generator.generate_json_report(str(json_file))
            reports_generated.append(str(json_file))

        if report_type in ["csv", "all"]:
            csv_file = Path(output_dir) / f"{filename}.csv"
            generator.generate_csv_report(str(csv_file))
            reports_generated.append(str(csv_file))

        if report_type in ["html", "all"]:
            html_file = Path(output_dir) / f"{filename}.html"
            generator.generate_html_report(str(html_file))
            reports_generated.append(str(html_file))

        logger.info(f"Reports generated: {', '.join(reports_generated)}")
        return True

    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}", exc_info=True)
        return False


def start_api_server(port):
    """Start REST API server"""
    try:
        from api_server import app

        logger.info(f"Starting API server on port {port}")
        app.run(host="0.0.0.0", port=port, debug=False)
    except Exception as e:
        logger.error(f"Failed to start API server: {str(e)}", exc_info=True)


def main():
    """Main application entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # API server mode
        if args.api:
            start_api_server(args.api_port)

        # Scanning mode
        elif args.url:
            # Validate URL
            if not args.url.startswith(("http://", "https://")):
                logger.error("URL must start with http:// or https://")
                sys.exit(1)

            # Prepare config
            config = {
                "timeout": args.timeout,
                "max_urls": args.max_urls,
                "skip_ssl": args.skip_ssl,
                "no_external": args.no_external,
            }

            # Run scan
            results = scan_target(args.url, args.depth, config)

            if results is not None:
                # Generate reports
                if generate_reports(
                    results, args.report, args.filename, args.output_dir
                ):
                    logger.info("Scan and reporting completed successfully")
                    print(
                        f"\n✓ Scan complete! Reports saved to '{args.output_dir}' directory"
                    )
                else:
                    sys.exit(1)
            else:
                sys.exit(1)

        else:
            parser.print_help()
            sys.exit(0)

    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
