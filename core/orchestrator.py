import json
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from core.subdomains import run_sublist3r
from core.nmap_scan import nmap_service_scan, infer_scheme_from_nmap
from core.http_probe import probe_base
from core.crawler import crawl_site
from core.cms_detect import detect_cms
from core.waf_detect import detect_waf
from core.tls_audit import tls_audit
from core.cve_nvd import lookup_nvd
from core.report_pdf import write_pdf
from core.utils import is_ip, reverse_dns_lookup
from core.ip_enrich import resolve_domain_to_ips, reverse_dns, resolve_hostname, rdap_ip_lookup, geo_ip_api
from core.nmap_parse import parse_nmap_text
from core.risk_score import compute_risk_score
from core.version_matcher import is_version_affected
from core.utils_timer import step_timer
from core.host_discovery import discover_hosts
from core.nmap_xml_parser import parse_nmap_xml
from core.masscan_scan import run_masscan
from core.httpx_probe import run_httpx
from core.nuclei_scan import run_nuclei
from core.xss_scan import scan_xss
from core.sqli_scan import scan_sqli
from core.security_headers import analyze_security_headers
from core.cookie_audit import analyze_cookies
from core.cors_check import run_cors_checks
from core.dns_audit import run_dns_audit
from core.service_checks import run_service_checks
from core.takeover import check_subdomain_takeover
from core.robots_sitemap import get_seed_urls
from core.http_methods import run_http_method_tests
from core.open_redirect import scan_open_redirects
from core.js_secrets import scan_js_secrets
from core.dir_bruteforce import run_dir_bruteforce
from core.screenshot import run_screenshots
from core.shodan_lookup import run_shodan_lookup
from core.cloud_buckets import run_cloud_bucket_detection
from core.param_discovery import run_param_discovery
from core.theharvester import run_theharvester
from core.jwt_analysis import scan_jwt_tokens
from core.dom_xss import scan_dom_xss
from yaspin import yaspin
from yaspin.spinners import Spinners
from tqdm import tqdm
from pathlib import Path
from colorama import Fore, Style
import logging
import ipaddress
import re
from urllib.parse import urlparse

log = logging.getLogger("recon-audit")

def risk_badge(level, score):
    if level == "HIGH":
        return f"{Fore.RED}[ HIGH ]{Style.RESET_ALL} ({score})"
    elif level == "MEDIUM":
        return f"{Fore.YELLOW}[ MEDIUM ]{Style.RESET_ALL} ({score})"
    elif level == "LOW":
        return f"{Fore.GREEN}[ LOW ]{Style.RESET_ALL} ({score})"
    elif level == "POTENTIAL":
        return f"{Fore.MAGENTA}[ POTENTIAL ]{Style.RESET_ALL} ({score})"
    else:
        return f"[ {level} ] ({score})"

def _analyze_subdomain(sub: str, timeout: int, crawl_depth: int, max_pages: int, do_crawl: bool, use_nvd: bool, base_dir: Path, full_scan=False, do_xss=True, do_sqli=True, do_dir_bruteforce=True, do_dns_audit=True, do_service_checks=True, do_takeover=True, do_screenshot=True, do_shodan=True, do_cloud_buckets=True, do_param_discovery=True, do_theharvester=True, do_jwt=True, do_dom_xss=True, shodan_api_key=None, nmap_semaphore=None, nmap_timeout=None):
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    with step_timer(f"Full analysis for {sub}"):
        res = {"subdomain": sub}

        resolved_ips = []

        try:
            if is_ip(sub):
                resolved_ips = [sub]
            else:
                resolved_ips = resolve_domain_to_ips(sub)
        except Exception:
            resolved_ips = []

        res["resolved_ips"] = resolved_ips
        
        if is_ip(sub) and resolved_ips:
            log.info("No IP resolved for %s. %s already IP", sub, sub)
        elif not is_ip(sub) and resolved_ips:
            log.info("Resolved IPs for %s → %s", sub, ", ".join(resolved_ips))
        else:
            log.info("No IP resolved for %s", sub)

        ip_enrichment = []

        for ip in resolved_ips:
            ip_info = {
                "ip": ip,
                "reverse_dns": resolve_hostname(ip),
                "rdap": rdap_ip_lookup(ip),
                "geo": geo_ip_api(ip)
            }

            ip_enrichment.append(ip_info)

        res["ip_enrichment"] = ip_enrichment

        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if resolved_ips:
            log.info("Enriching IPs: %s", ", ".join(resolved_ips))

        # theHarvester OSINT (emails, extra subdomains) — domain targets only
        res["theharvester"] = {}
        if do_theharvester and not is_ip(sub):
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"theHarvester OSINT ({sub})"):
                res["theharvester"] = run_theharvester(sub)
            h = res["theharvester"]
            if h.get("emails"):
                log.info("theHarvester emails on %s: %s", sub, h["emails"][:5])
            if h.get("subdomains"):
                log.info("theHarvester subdomains on %s: %d", sub, len(h["subdomains"]))

        # DNS audit (zone transfer, SPF/DMARC/DKIM, wildcard)
        res["dns_audit"] = {}
        if do_dns_audit and not is_ip(sub):
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"DNS audit ({sub})"):
                res["dns_audit"] = run_dns_audit(sub)
            axfr = res["dns_audit"].get("zone_transfer", {})
            if axfr.get("vulnerable"):
                log.info("AXFR zone transfer VULNERABLE on %s", sub)

        # Subdomain takeover check
        res["takeover"] = {}
        if do_takeover and not is_ip(sub):
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"Takeover check ({sub})"):
                res["takeover"] = check_subdomain_takeover(sub)
            if res["takeover"].get("vulnerable"):
                log.info("Potential takeover on %s → %s", sub, res["takeover"].get("warning"))

        # 1) Masscan (fast port scan)
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        with step_timer(f"Masscan scan {sub}"):
            masscan_results = run_masscan(sub)

        ports = []
        for ip in masscan_results:
            ports.extend(masscan_results[ip])

        if ports:
            log.info("Masscan found ports on %s → %s", sub, ports)
        else:
            log.info("Masscan found no ports on %s", sub)

        # 2) Nmap service scan
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        with step_timer(f"Nmap scan {sub}"):
            _sem = nmap_semaphore if nmap_semaphore is not None else threading.Semaphore(999)
            with _sem:
                with yaspin(Spinners.dots, text=f"Nmap scanning {sub}...") as spinner:

                    if ports:
                        port_str = ",".join(map(str, ports))
                        nmap_txt, xml_path = nmap_service_scan(sub, base_dir / "nmap", full_scan=False, ports=port_str, timeout=nmap_timeout)
                    else:
                        nmap_txt, xml_path = nmap_service_scan(sub, base_dir / "nmap", full_scan=True, timeout=nmap_timeout)

                    spinner.ok("✔")

        res["nmap_raw"] = nmap_txt
        res["nmap_xml"] = xml_path
        res["nmap_structured"] = parse_nmap_text(nmap_txt)
        scheme = infer_scheme_from_nmap(nmap_txt)
        res["scheme"] = scheme

        open_ports = res["nmap_structured"].get("open_ports", [])
        if open_ports:
            log.info("Open ports detected on %s: %s",
                    sub,
                    [p.get("port") for p in open_ports])
        else:
            log.info("No open ports detected on %s", sub)

        # Service-specific checks (FTP, SSH, SMTP, Redis, MongoDB, SMB)
        res["service_checks"] = {}
        if do_service_checks and open_ports:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"Service checks ({sub})"):
                host_for_checks = resolved_ips[0] if resolved_ips else sub
                res["service_checks"] = run_service_checks(host_for_checks, open_ports)
            warnings = [v.get("warning") for v in res["service_checks"].values() if isinstance(v, dict) and v.get("warning")]
            for w in warnings:
                log.info("Service vuln on %s → %s", sub, w)

        # Shodan IP lookup
        res["shodan"] = {}
        if do_shodan and resolved_ips:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"Shodan lookup ({sub})"):
                res["shodan"] = run_shodan_lookup(resolved_ips, api_key=shodan_api_key)

        # HTTPX probe (fast web detection)
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        with step_timer(f"HTTPX probing {sub}"):
            urls = []

            for p in open_ports:
                port = p.get("port")

                urls.append(f"{sub}:{port}")


            httpx_base_dir = base_dir / "httpx"
            httpx_base_dir.mkdir(parents=True, exist_ok=True)
            safe_sub = sub.replace("/", "_").replace(":", "_")

            httpx_results = run_httpx(
                urls,
                httpx_base_dir,
                target_name=safe_sub
            )

            res["httpx"] = httpx_results

            if httpx_results:
                log.info("HTTP services detected on %s → %d endpoints", sub, len(httpx_results))
            else:
                log.info("%d HTTP services endpoints detected on %s", len(httpx_results), sub)

        # Nuclei vulnerability scan
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        with step_timer(f"Nuclei vulnerability scan on ({sub})"):
            targets = [r.get("url") for r in httpx_results if r.get("url")]

            nuclei_results = []
            if targets:
                log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                with step_timer(f"Nuclei scan {sub}"):
                    nuclei_base_dir = base_dir / "nuclei" 
                    nuclei_base_dir.mkdir(parents=True, exist_ok=True)
                    safe_sub = sub.replace("/", "_").replace(":", "_")

                    nuclei_results = run_nuclei(
                        targets,
                        output_dir=nuclei_base_dir,
                        target_name=safe_sub
                    )

                    res["nuclei"] = nuclei_results

                    if nuclei_results:
                        log.info("Nuclei vulnerabilities found on %s → %d", sub, len(nuclei_results))
                    else:
                        res["nuclei"] = []
                        log.info("%d Nuclei vulnerabilities found on %s", len(nuclei_results), sub)
            else:
                log.info("No HTTP targets to scan with Nuclei on %s", sub)
                res["nuclei"] = []

        # 2) HTTP probe (headers/html snippet) — all web ports detected by httpx
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        http_probes = []
        with step_timer(f"HTTP probe ({sub})"):
            web_urls = [r.get("url") for r in httpx_results if r.get("url")]
            if not web_urls:
                # fallback: use scheme inferred from nmap on default port
                web_urls = [f"{scheme}://{sub}/"]
            for web_url in web_urls:
                parsed_url = urlparse(web_url)
                probe_scheme = parsed_url.scheme or scheme
                probe_host = parsed_url.netloc or sub  # includes port if non-standard, e.g. host:8080
                p = probe_base(probe_scheme, probe_host, timeout)
                p["_url"] = web_url
                http_probes.append(p)
                log.info("HTTP probe on %s → status %s", web_url, p.get("status", p.get("error")))

        # primary probe = first successful one (used for CMS/WAF/TLS detection)
        probe = next((p for p in http_probes if not p.get("error")), http_probes[0] if http_probes else {"error": "no web services"})
        res["http_probe"] = probe
        res["http_probes_all"] = http_probes

        headers = probe.get("headers", {})
        html_snip = probe.get("html_snippet", "")

        # 3) CMS detect
        res["cms"] = detect_cms(headers, html_snip)
        
        if res["cms"]:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            log.info("Detected CMS/Tech for %s: %s", sub, res["cms"])
        else:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            log.info("No CMS detected for %s", sub)


        # 4) WAF detect (heuristics)
        res["waf"] = detect_waf(headers, html_snip)
        if res["waf"]:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            log.info("Detected WAF for %s: %s", sub, res["waf"])

        # 5) TLS audit if https likely
        if scheme == "https":
            res["tls"] = tls_audit(sub, 443)
        else:
            res["tls"] = {}

        if res["tls"]:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            log.info("TLS detected on %s - protocol: %s",
                    sub,
                    res["tls"].get("protocol"))

        # Security headers analysis
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        with step_timer(f"Security headers ({sub})"):
            res["security_headers"] = analyze_security_headers(headers)
        missing_h = [m["short"] for m in res["security_headers"].get("missing", [])]
        if missing_h:
            log.info("Missing security headers on %s: %s", sub, missing_h)

        # Cookie security audit
        with step_timer(f"Cookie audit ({sub})"):
            res["cookies"] = analyze_cookies(headers)
        if res["cookies"]:
            log.info("Insecure cookies on %s: %d", sub, len(res["cookies"]))

        # robots.txt / sitemap (seed URLs discovery)
        res["robots_sitemap"] = {}
        seed_urls = []
        if httpx_results:
            primary_web_url = web_urls[0] if web_urls else f"{scheme}://{sub}/"
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"robots.txt / sitemap ({sub})"):
                robots_data = get_seed_urls(primary_web_url, timeout)
            res["robots_sitemap"] = robots_data
            seed_urls = robots_data.get("seed_urls", [])
            if seed_urls:
                log.info("robots.txt/sitemap seeded %d URLs on %s", len(seed_urls), sub)

        # 6) Crawl pages — on all web ports found by httpx, seeded with robots/sitemap, seeded with robots/sitemap
        pages = []
        if do_crawl:
            crawl_targets = [
                p.get("final_url") or p.get("_url")
                for p in http_probes
                if not p.get("error") and (p.get("final_url") or p.get("_url"))
            ]
            if not crawl_targets and not probe.get("error"):
                crawl_targets = [probe.get("final_url") or f"{scheme}://{sub}/"]
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"Crawling ({sub})"):
                for crawl_url in crawl_targets:
                    log.info("Crawling %s ...", crawl_url)
                    sub_pages = crawl_site(crawl_url, depth=crawl_depth, max_pages=max_pages, timeout=timeout)
                    pages.extend(sub_pages)
                # Also crawl seed URLs from robots/sitemap not already covered
                crawled_origins = {urlparse(p.get("url", "")).netloc for p in pages}
                for seed_url in seed_urls[:20]:
                    if urlparse(seed_url).netloc not in crawled_origins:
                        sub_pages = crawl_site(seed_url, depth=1, max_pages=20, timeout=timeout)
                        pages.extend(sub_pages)
        res["pages"] = pages

        log.info("Crawl finished on %s - %d pages found",
            sub,
            len(pages))

        # 7) Passive login form detection (only if we crawled)
        if pages:
            from core.form_analyzer import detect_login_forms
            res["login_forms"] = detect_login_forms(pages, timeout=timeout)
        else:
            res["login_forms"] = []

        if res["login_forms"]:
            log.info("Login forms detected on %s: %d",
                    sub,
                    len(res["login_forms"]))

        # 7b) XSS scan (reflected) on crawled pages
        res["xss_findings"] = []
        if do_xss and pages:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"XSS scan ({sub})"):
                xss = scan_xss(pages, timeout=timeout)
            res["xss_findings"] = xss
            if xss:
                log.info("XSS findings on %s → %d potential reflected XSS", sub, len(xss))
            else:
                log.info("No reflected XSS found on %s", sub)
        elif not pages:
            log.info("XSS scan skipped for %s — no crawled pages", sub)

        # 7c) SQL injection scan (SQLmap) on crawled pages
        res["sqli_findings"] = []
        if do_sqli and pages:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"SQLi scan ({sub})"):
                sqli = scan_sqli(pages, output_dir=base_dir, timeout=timeout)
            res["sqli_findings"] = sqli
            if sqli:
                log.info("SQLi findings on %s → %d injection(s) confirmed", sub, len(sqli))
            else:
                log.info("No SQL injection found on %s", sub)
        elif not pages:
            log.info("SQLi scan skipped for %s — no crawled pages", sub)

        # 7d) CORS misconfiguration checks
        res["cors_findings"] = []
        if pages:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"CORS check ({sub})"):
                res["cors_findings"] = run_cors_checks(pages, timeout=timeout)
            if res["cors_findings"]:
                log.info("CORS misconfig on %s → %d findings", sub, len(res["cors_findings"]))

        # 7e) HTTP dangerous methods
        res["http_methods"] = []
        if pages:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"HTTP methods ({sub})"):
                res["http_methods"] = run_http_method_tests(pages, timeout=timeout)
            if res["http_methods"]:
                log.info("Dangerous HTTP methods on %s → %d", sub, len(res["http_methods"]))

        # 7f) Open redirect scan
        res["open_redirects"] = []
        if pages:
            with step_timer(f"Open redirect ({sub})"):
                res["open_redirects"] = scan_open_redirects(pages, timeout=timeout)
            if res["open_redirects"]:
                log.info("Open redirects on %s → %d", sub, len(res["open_redirects"]))

        # 7g-1) JWT token analysis
        res["jwt_findings"] = []
        if do_jwt and (pages or headers):
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"JWT analysis ({sub})"):
                res["jwt_findings"] = scan_jwt_tokens(pages, headers=headers, timeout=timeout)
            if res["jwt_findings"]:
                log.info("JWT tokens found on %s → %d", sub, len(res["jwt_findings"]))

        # 7g-2) DOM XSS via Playwright
        res["dom_xss"] = []
        if do_dom_xss and pages:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"DOM XSS ({sub})"):
                res["dom_xss"] = scan_dom_xss(pages, timeout=timeout)
            if res["dom_xss"]:
                log.info("DOM XSS findings on %s → %d", sub, len(res["dom_xss"]))

        # 7g) JavaScript secrets extraction
        res["js_secrets"] = []
        if pages:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"JS secrets ({sub})"):
                res["js_secrets"] = scan_js_secrets(pages, timeout=timeout)
            if res["js_secrets"]:
                log.info("JS secrets found on %s → %d", sub, len(res["js_secrets"]))

        # 7g-3) Parameter discovery via arjun
        res["param_discovery"] = []
        if do_param_discovery and httpx_results:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            param_urls = [r.get("url") for r in httpx_results[:5] if r.get("url")]
            with step_timer(f"Param discovery ({sub})"):
                res["param_discovery"] = run_param_discovery(param_urls, timeout=120)
            if res["param_discovery"]:
                log.info("Params discovered on %s → %d endpoints", sub, len(res["param_discovery"]))

        # 7g-4) Cloud bucket detection
        res["cloud_buckets"] = []
        if do_cloud_buckets:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            bucket_target = sub if not is_ip(sub) else (resolved_ips[0] if resolved_ips else sub)
            with step_timer(f"Cloud bucket detection ({sub})"):
                res["cloud_buckets"] = run_cloud_bucket_detection(bucket_target, pages=pages, timeout=timeout)
            if res["cloud_buckets"]:
                log.info("Cloud buckets found for %s → %d", sub, len(res["cloud_buckets"]))

        # 7h) Directory brute-force
        res["dir_bruteforce"] = []
        if do_dir_bruteforce and httpx_results:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            dirbust_dir = base_dir / "dirbust"
            all_dirbust = []
            for httpx_r in httpx_results[:5]:  # Limit to 5 endpoints
                target_url = httpx_r.get("url", "")
                if target_url:
                    with step_timer(f"Dir bruteforce {target_url}"):
                        hits = run_dir_bruteforce(target_url, output_dir=dirbust_dir, timeout=120)
                    all_dirbust.extend(hits)
            res["dir_bruteforce"] = all_dirbust
            if all_dirbust:
                log.info("Dir bruteforce on %s → %d paths found", sub, len(all_dirbust))

        # 7i) Screenshots
        res["screenshots"] = []
        if do_screenshot and httpx_results:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            screenshot_urls = [r.get("url") for r in httpx_results if r.get("url")]
            with step_timer(f"Screenshots ({sub})"):
                res["screenshots"] = run_screenshots(screenshot_urls, base_dir / "screenshots")
            if res["screenshots"]:
                log.info("Screenshots captured for %s → %d", sub, len(res["screenshots"]))

        # 8) CVE lookup (NVD) from detected services
        res["cves"] = []

        if use_nvd:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"CVE lookup {sub}"):
                services = {}

                # 1️⃣ Services detected via Nmap
                nmap_s = res.get("nmap_structured", {}) or {}
                open_ports = nmap_s.get("open_ports", []) or []

                for p in open_ports:
                    product = p.get("product")
                    version = p.get("version_raw")

                    if product and product.strip().replace("?", ""):
                        name = product.lower().strip()

                        clean_version = None

                        if version:
                            # Exemple version_raw: "OpenSSH 10.0p2 Debian 1"
                            version_str = str(version)

                            # Extract the first full version including pX suffix
                            match = re.search(r"\d+\.\d+[a-zA-Z0-9\-]*", version_str)
                            if match:
                                clean_version = match.group(0)

                        services[name] = clean_version

                log.info("Detected services for CVE search: %s", services)

                # 2️⃣ Web technologies detected (CMS)
                for tech in res.get("cms", []) or []:
                    name = tech.lower().strip()

                    # Strip unnecessary prefixes
                    if ":" in name:
                        name = name.split(":", 1)[1].strip()

                    if name not in services:
                        services[name] = None

                # 3️⃣ Headers HTTP
                if isinstance(headers, dict):
                    if "Server" in headers:
                        server_val = headers["Server"].lower().strip()
                        if "/" in server_val:
                            server_val = server_val.split("/")[0]
                        services[server_val] = None
                    if "X-Powered-By" in headers:
                        services[headers["X-Powered-By"].lower()] = None

                # 🔎 Recherche CVE pour chaque service
                seen = set()

                for service_name, version in services.items():

                    if not service_name or service_name in seen:
                        continue

                    seen.add(service_name)

                    if version:
                        query = f"{service_name} {version}"
                    else:
                        query = service_name

                    log.info("Searching CVEs for: %s", query)

                    with yaspin(Spinners.line, text="Querying NVD API...") as spinner:
                        cve_results = lookup_nvd(query)
                        spinner.ok("✔")

                    filtered = []

                    for cve in cve_results:
                        summary = cve.get("summary", "")
                        
                        if version:
                            if is_version_affected(version, summary):
                                cve["confirmed"] = True
                                filtered.append(cve)
                            else:
                                continue
                        else:
                            cve["confirmed"] = False
                            filtered.append(cve)

                    res["cves"].extend(filtered)

        # === RISK SCORE ===
        res["risk"] = compute_risk_score(res)

        badge = risk_badge(
            res["risk"].get("level"),
            res["risk"].get("score")
        )
        
        badge = badge.replace("\x1b[32m", "").replace("\x1b[0m", "")

        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Risk assessment for %s → %s", sub, badge)


        return res

def file_size_mb(path):
    path = Path(path)
    
    if not path.exists():
        return 0
    
    return round(path.stat().st_size / (1024 * 1024), 2)

def run_audit(target: str, threads: int, crawl_depth: int, max_pages: int, timeout: int,
              use_nvd: bool, do_crawl: bool, generate_pdf: bool, write_json: bool,
              full_scan=False, do_xss=True, do_sqli=True, output_dir=None,
              scan_rate_delay=0.0, do_dir_bruteforce=True, do_dns_audit=True,
              do_service_checks=True, do_takeover=True, do_screenshot=True,
              do_shodan=True, do_cloud_buckets=True, do_param_discovery=True,
              do_theharvester=True, do_jwt=True, do_dom_xss=True,
              shodan_api_key=None, nmap_timeout=None, nmap_concurrency=2):

    if output_dir:
        base_dir = Path(output_dir)
    else:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        base_dir = Path("results") / f"{target}_{ts}"

    base_dir.mkdir(parents=True, exist_ok=True)

    # ── Optional tool availability check (shown once at startup) ──────────
    import shutil
    _opt_tools = []
    if do_shodan:
        try:
            import shodan as _s  # noqa: F401
            import os as _os
            if not (shodan_api_key or _os.environ.get("SHODAN_API_KEY")):
                _opt_tools.append("Shodan (SHODAN_API_KEY not set — will be skipped)")
        except ImportError:
            _opt_tools.append("Shodan (package not installed: pip install shodan)")
    if do_param_discovery and not shutil.which("arjun"):
        _opt_tools.append("arjun (not found: pip install arjun)")
    if do_dom_xss:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError:
            _opt_tools.append("Playwright/DOM XSS (not installed: pip install playwright && playwright install chromium)")
    if do_theharvester and not (shutil.which("theHarvester") or shutil.which("theharvester")):
        _opt_tools.append("theHarvester (not found — install from https://github.com/laramies/theHarvester)")
    if _opt_tools:
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Optional tools not available (will be skipped):")
        for t in _opt_tools:
            log.info("  ✗ %s", t)
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    # ──────────────────────────────────────────────────────────────────────

    subs = []
    subsip = []

    domain = None

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)

            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            log.info("Target detected as network range: %s", target)

            hosts = []

            for i, ip in enumerate(network.hosts()):
                if i >= 1024:
                    log.warning("Network too large. Limiting to first 1024 hosts.")
                    break
                hosts.append(str(ip))

            log.info("Total IPs in range: %d", len(hosts))

            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            log.info("Starting host discovery (ping sweep)...")

            # Pass the CIDR range directly so nmap scans it in one optimised pass
            alive_hosts = discover_hosts([target])

            if not alive_hosts:
                log.warning("No alive hosts detected.")
                return

            log.info("Alive hosts detected: %d", len(alive_hosts))
            log.info("Alive IPs: %s", alive_hosts)

            subs = alive_hosts

        except Exception:
            log.error("Invalid network range: %s", target)
            return

    elif is_ip(target):
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Target is detected as IP address.")

        domain = reverse_dns_lookup(target)

        if domain:
            log.info("Reverse DNS found domain: %s", domain)

            # On inclut l'IP + le domaine
            subs = [target]

            with step_timer(f"Sublist3r enumeration on {domain}"):
                domain_subs = run_sublist3r(domain, out_dir=base_dir / "sublist3r")
            subs.extend(domain_subs)

            subs = list(set(subs))

        else:
            log.info("No reverse DNS domain found. Running scan directly on IP.")
            subsip = [target]

    else:
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        log.info("Target is detected as domain.")
        with step_timer(f"Sublist3r enumeration on {target}"):
            subs = run_sublist3r(target, out_dir=base_dir / "sublist3r")

    log.info("Total targets to analyze: %d", len(subs))
    if subs:
        log.info("Subdomains found: %s", subs)
    else:
        log.info("No subdomains found for %s", ", ".join(subsip))



    report = {
        "input_target": target,
        "is_ip": is_ip(target),
        "reverse_dns": resolve_hostname(target) if is_ip(target) else None,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "subdomains": {}
    }

    # Multi-thread analysis
    start_time = datetime.now()
    total_cve_found = 0

    _nmap_semaphore = threading.Semaphore(max(1, nmap_concurrency))

    with ThreadPoolExecutor(max_workers=max(2, threads)) as ex:
        _extra_kwargs = dict(
            do_dir_bruteforce=do_dir_bruteforce,
            do_dns_audit=do_dns_audit,
            do_service_checks=do_service_checks,
            do_takeover=do_takeover,
            do_screenshot=do_screenshot,
            do_shodan=do_shodan,
            do_cloud_buckets=do_cloud_buckets,
            do_param_discovery=do_param_discovery,
            do_theharvester=do_theharvester,
            do_jwt=do_jwt,
            do_dom_xss=do_dom_xss,
            shodan_api_key=shodan_api_key,
            nmap_semaphore=_nmap_semaphore,
            nmap_timeout=nmap_timeout,
        )
        if subs:
            futures = []
            for s in subs:
                futures.append(ex.submit(_analyze_subdomain, s, timeout, crawl_depth, max_pages, do_crawl, use_nvd, base_dir, full_scan, do_xss, do_sqli, **_extra_kwargs))
                if scan_rate_delay > 0:
                    time.sleep(scan_rate_delay)
        else:
            futures = []
            for s in subsip:
                futures.append(ex.submit(_analyze_subdomain, s, timeout, crawl_depth, max_pages, do_crawl, use_nvd, base_dir, full_scan, do_xss, do_sqli, **_extra_kwargs))
                if scan_rate_delay > 0:
                    time.sleep(scan_rate_delay)

        if subs:
            for sub, fut in zip(
                subs,
                tqdm(
                    futures,
                    total=len(futures),
                    desc="Recon Progress",
                    dynamic_ncols=True,
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
                )
            ):
                try:
                    data = fut.result()

                    # ✅ LIVE CVE COUNTER
                    cve_count = len(data.get("cves", []))
                    total_cve_found += cve_count
                    tqdm.write(f"🔎 CVE found for {sub}: {cve_count} (Total: {total_cve_found})")
                    xss_count  = len(data.get("xss_findings", []))
                    sqli_count = len(data.get("sqli_findings", []))
                    if xss_count:  tqdm.write(f"⚠  XSS findings for {sub}: {xss_count}")
                    if sqli_count: tqdm.write(f"💉 SQLi findings for {sub}: {sqli_count}")
                    js_count = len(data.get("js_secrets", []))
                    if js_count:   tqdm.write(f"🔑 JS secrets for {sub}: {js_count}")

                    # ✅ Report save
                    report["subdomains"][sub] = {
                        "scheme": data.get("scheme"),
                        "resolved_ips": data.get("resolved_ips", []),
                        "ip_enrichment": data.get("ip_enrichment", []),
                        "tls": data.get("tls"),
                        "cms": data.get("cms", []),
                        "waf": data.get("waf", []),
                        "pages": data.get("pages", []),
                        "login_forms": data.get("login_forms", []),
                        "xss_findings": data.get("xss_findings", []),
                        "sqli_findings": data.get("sqli_findings", []),
                        "cves": data.get("cves", []),
                        "risk": data.get("risk"),
                        "httpx": data.get("httpx", []),
                        "nuclei": data.get("nuclei", []),
                        "masscan": data.get("masscan", {}),
                        "nmap_raw": data.get("nmap_raw"),
                        "nmap_structured": data.get("nmap_structured"),
                        "security_headers": data.get("security_headers", {}),
                        "cookies": data.get("cookies", []),
                        "cors_findings": data.get("cors_findings", []),
                        "dns_audit": data.get("dns_audit", {}),
                        "service_checks": data.get("service_checks", {}),
                        "takeover": data.get("takeover", {}),
                        "robots_sitemap": data.get("robots_sitemap", {}),
                        "http_methods": data.get("http_methods", []),
                        "open_redirects": data.get("open_redirects", []),
                        "js_secrets": data.get("js_secrets", []),
                        "dir_bruteforce": data.get("dir_bruteforce", []),
                        "screenshots": data.get("screenshots", []),
                        "shodan": data.get("shodan", {}),
                        "cloud_buckets": data.get("cloud_buckets", []),
                        "param_discovery": data.get("param_discovery", []),
                        "theharvester": data.get("theharvester", {}),
                        "jwt_findings": data.get("jwt_findings", []),
                        "dom_xss": data.get("dom_xss", []),
                    }

                    safe_sub = sub.replace("/", "_").replace(":", "_")

                    # Save raw nmap per sub
                    nmap_base_dir = base_dir / "nmap"
                    nmap_base_dir.mkdir(parents=True, exist_ok=True)
                    with open(nmap_base_dir / f"nmap_{safe_sub}.txt", "w", encoding="utf-8") as f:
                        f.write(data.get("nmap_raw", ""))
                    
                    xml_path = data.get("nmap_xml")

                    log.info("Nmap XML saved → %s", xml_path)

                    xml_path = Path(xml_path)
                    if xml_path.exists() and xml_path.stat().st_size > 200:

                        try:
                            parsed = parse_nmap_xml(xml_path)

                            json_path = nmap_base_dir / f"nmap_{safe_sub}.json"

                            with open(json_path, "w") as jf:
                                json.dump(parsed, jf, indent=2)

                            log.info("Nmap JSON saved → %s", json_path)

                        except Exception as e:
                            log.warning("Failed to parse Nmap XML for %s: %s", sub, e)

                except Exception as e:
                    tqdm.write(f"❌ Error analyzing {sub}: {e}")
                    log.error("Error analyzing %s: %s", sub, e)
        else:
            for sub, fut in zip(
                subsip,
                tqdm(
                    futures,
                    total=len(futures),
                    desc="Recon Progress",
                    dynamic_ncols=True,
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
                )
            ):
                try:
                    data = fut.result()

                    # ✅ LIVE CVE COUNTER (subsip loop)
                    cve_count = len(data.get("cves", []))
                    total_cve_found += cve_count
                    tqdm.write(f"🔎 CVE found for {sub}: {cve_count} (Total: {total_cve_found})")
                    xss_count  = len(data.get("xss_findings", []))
                    sqli_count = len(data.get("sqli_findings", []))
                    if xss_count:  tqdm.write(f"⚠  XSS findings for {sub}: {xss_count}")
                    if sqli_count: tqdm.write(f"💉 SQLi findings for {sub}: {sqli_count}")
                    js_count = len(data.get("js_secrets", []))
                    if js_count:   tqdm.write(f"🔑 JS secrets for {sub}: {js_count}")

                    # ✅ Report save
                    report["subdomains"][sub] = {
                        "scheme": data.get("scheme"),
                        "resolved_ips": data.get("resolved_ips", []),
                        "ip_enrichment": data.get("ip_enrichment", []),
                        "tls": data.get("tls"),
                        "cms": data.get("cms", []),
                        "waf": data.get("waf", []),
                        "pages": data.get("pages", []),
                        "login_forms": data.get("login_forms", []),
                        "xss_findings": data.get("xss_findings", []),
                        "sqli_findings": data.get("sqli_findings", []),
                        "cves": data.get("cves", []),
                        "risk": data.get("risk"),
                        "httpx": data.get("httpx", []),
                        "nuclei": data.get("nuclei", []),
                        "masscan": data.get("masscan", {}),
                        "nmap_raw": data.get("nmap_raw"),
                        "nmap_structured": data.get("nmap_structured"),
                        "security_headers": data.get("security_headers", {}),
                        "cookies": data.get("cookies", []),
                        "cors_findings": data.get("cors_findings", []),
                        "dns_audit": data.get("dns_audit", {}),
                        "service_checks": data.get("service_checks", {}),
                        "takeover": data.get("takeover", {}),
                        "robots_sitemap": data.get("robots_sitemap", {}),
                        "http_methods": data.get("http_methods", []),
                        "open_redirects": data.get("open_redirects", []),
                        "js_secrets": data.get("js_secrets", []),
                        "dir_bruteforce": data.get("dir_bruteforce", []),
                        "screenshots": data.get("screenshots", []),
                        "shodan": data.get("shodan", {}),
                        "cloud_buckets": data.get("cloud_buckets", []),
                        "param_discovery": data.get("param_discovery", []),
                        "theharvester": data.get("theharvester", {}),
                        "jwt_findings": data.get("jwt_findings", []),
                        "dom_xss": data.get("dom_xss", []),
                    }

                    safe_sub = sub.replace("/", "_").replace(":", "_")

                    # Save raw nmap per sub
                    nmap_base_dir = base_dir / "nmap"
                    nmap_base_dir.mkdir(parents=True, exist_ok=True)
                    with open(nmap_base_dir / f"nmap_{safe_sub}.txt", "w", encoding="utf-8") as f:
                        f.write(data.get("nmap_raw", ""))
                    
                    xml_path = data.get("nmap_xml")

                    log.info("Nmap XML saved → %s", xml_path)

                    if xml_path and xml_path.exists() and xml_path.stat().st_size > 50:

                        try:
                            parsed = parse_nmap_xml(xml_path)

                            json_path = nmap_base_dir / f"nmap_{safe_sub}.json"

                            with open(json_path, "w") as jf:
                                json.dump(parsed, jf, indent=2)

                            log.info("Nmap JSON saved → %s", json_path)

                        except Exception as e:
                            log.warning("Failed to parse Nmap XML for %s: %s", sub, e)

                except Exception as e:
                    tqdm.write(f"❌ Error analyzing {sub}: {e}")
                    log.error("Error analyzing %s: %s", sub, e)


    json_path = base_dir / "report.json"
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("Writing JSON report → %s", json_path)
    if write_json:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        size = file_size_mb(json_path)
        log.info("JSON written (%.2f MB)", size)


    pdf_path = base_dir / "report.pdf"
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("Generating PDF report → %s", pdf_path)
    if generate_pdf:
        with step_timer("PDF generation"):
            write_pdf(report, pdf_path)
        size = file_size_mb(pdf_path)
        log.info("PDF generated (%.2f MB)", size)

    # TIMER SUMMARY
    total_time = (datetime.now() - start_time).total_seconds()

    log.info("")
    log.info("")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info(f"{Fore.CYAN}✔ Audit Completed{Style.RESET_ALL}")
    log.info(f"⏱ Total duration: {total_time:.2f} sec")
    if subs:
        log.info(f"🎯 Targets analyzed: {len(subs)}")
    else:
        log.info(f"🎯 Targets analyzed: {len(subsip)}")
    log.info(f"🐞 Total CVE found: {total_cve_found}")
    log.info(f"📁 Output directory: {base_dir}")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    return {"base_dir": base_dir, "json": json_path, "pdf": pdf_path if generate_pdf else None}
