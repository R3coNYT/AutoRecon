import argparse
from core.orchestrator import run_audit
from core.logger import setup_logging

def build_parser():
    p = argparse.ArgumentParser(
        prog="recon-audit",
        description="Professional Recon & Audit Framework (authorized targets only)."
    )
    p.add_argument("-t", "--target", required=True, help="Root domain (example.com)")
    p.add_argument("--threads", type=int, default=12, help="Worker threads (default: 12)")
    p.add_argument("--crawl-depth", type=int, default=2, help="Crawler depth per subdomain (default: 2)")
    p.add_argument("--max-pages", type=int, default=120, help="Max pages per subdomain (default: 120)")
    p.add_argument("--timeout", type=int, default=7, help="HTTP timeout seconds (default: 7)")
    p.add_argument("--no-nvd", action="store_true", help="Disable NVD CVE lookup")
    p.add_argument("--no-crawl", action="store_true", help="Disable crawling")
    p.add_argument("--no-xss", action="store_true", help="Disable reflected XSS scanning")
    p.add_argument("--no-sqli", action="store_true", help="Disable SQL injection scanning (SQLmap)")
    p.add_argument("--no-dir-bruteforce", action="store_true", help="Disable directory brute-forcing")
    p.add_argument("--no-dns-audit", action="store_true", help="Disable DNS security audit (AXFR, SPF/DMARC)")
    p.add_argument("--no-service-checks", action="store_true", help="Disable service-specific checks (FTP, SSH, Redis...)")
    p.add_argument("--no-takeover", action="store_true", help="Disable subdomain takeover detection")
    p.add_argument("--no-screenshot", action="store_true", help="Disable web screenshots (gowitness)")
    p.add_argument("--no-shodan", action="store_true", help="Disable Shodan IP lookup")
    p.add_argument("--no-cloud-buckets", action="store_true", help="Disable cloud bucket detection (S3, GCS, Azure)")
    p.add_argument("--no-param-discovery", action="store_true", help="Disable parameter discovery (arjun)")
    p.add_argument("--no-theharvester", action="store_true", help="Disable subdomain OSINT (theHarvester)")
    p.add_argument("--no-jwt", action="store_true", help="Disable JWT token analysis")
    p.add_argument("--no-dom-xss", action="store_true", help="Disable DOM XSS scan (Playwright)")
    p.add_argument("--shodan-key", default=None, metavar="KEY",
                   help="Shodan API key (overrides SHODAN_API_KEY env var)")
    p.add_argument("--scan-rate-delay", type=float, default=0.0, metavar="SECONDS",
                   help="Delay in seconds between parallel scan submissions (default: 0.0)")
    p.add_argument("--pdf", action="store_true", help="Generate PDF report")
    p.add_argument("--json", action="store_true", help="Always write JSON report")
    p.add_argument("--full", action="store_true", help="Run full Nmap scan (all ports)")
    p.add_argument("--output-dir", help="Custom output directory", default=None)
    return p

def main(cli_args=None):
    parser = build_parser()
    args = parser.parse_args(cli_args)

    log = setup_logging(args.target, args.output_dir)
    log.info("Starting audit for target: %s", args.target)

    result_paths = run_audit(
        target=args.target,
        threads=args.threads,
        crawl_depth=args.crawl_depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
        use_nvd=(not args.no_nvd),
        do_crawl=(not args.no_crawl),
        do_xss=(not args.no_xss),
        do_sqli=(not args.no_sqli),
        do_dir_bruteforce=(not args.no_dir_bruteforce),
        do_dns_audit=(not args.no_dns_audit),
        do_service_checks=(not args.no_service_checks),
        do_takeover=(not args.no_takeover),
        do_screenshot=(not args.no_screenshot),
        do_shodan=(not args.no_shodan),
        do_cloud_buckets=(not args.no_cloud_buckets),
        do_param_discovery=(not args.no_param_discovery),
        do_theharvester=(not args.no_theharvester),
        do_jwt=(not args.no_jwt),
        do_dom_xss=(not args.no_dom_xss),
        shodan_api_key=args.shodan_key,
        scan_rate_delay=args.scan_rate_delay,
        generate_pdf=args.pdf,
        write_json=(args.json or True),
        full_scan=args.full,
        output_dir=args.output_dir
    )

    log.info("")
    log.info("Done. Results: %s", result_paths)

if __name__ == "__main__":
    main()
