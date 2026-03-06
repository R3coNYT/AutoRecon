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
        generate_pdf=args.pdf,
        write_json=(args.json or True),
        full_scan=args.full,
        output_dir=args.output_dir
    )

    log.info("")
    log.info("Done. Results: %s", result_paths)

if __name__ == "__main__":
    main()
