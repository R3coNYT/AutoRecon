import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from core.ip_enrich import resolve_domain_to_ips, reverse_dns, rdap_ip_lookup, geo_ip_api
from core.nmap_parse import parse_nmap_text
from core.risk_score import compute_risk_score
from core.version_matcher import is_version_affected
from core.utils_timer import step_timer
from core.host_discovery import discover_hosts
from core.nmap_xml_parser import parse_nmap_xml
from core.masscan_scan import run_masscan
from core.httpx_probe import run_httpx
from core.nuclei_scan import run_nuclei
from yaspin import yaspin
from yaspin.spinners import Spinners
from tqdm import tqdm
from pathlib import Path
from colorama import Fore, Style
import logging
import ipaddress
import re

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

def _analyze_subdomain(sub: str, timeout: int, crawl_depth: int, max_pages: int, do_crawl: bool, use_nvd: bool, base_dir: Path, full_scan=False):
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
                "reverse_dns": reverse_dns(ip),
                "rdap": rdap_ip_lookup(ip),
                "geo": geo_ip_api(ip)
            }

            ip_enrichment.append(ip_info)

        res["ip_enrichment"] = ip_enrichment

        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if resolved_ips:
            log.info("Enriching IPs: %s", ", ".join(resolved_ips))

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
            with yaspin(Spinners.dots, text=f"Nmap scanning {sub}...") as spinner:

                if ports:
                    port_str = ",".join(map(str, ports))
                    nmap_txt, xml_path = nmap_service_scan(sub, base_dir / "nmap", full_scan, ports=port_str)
                else:
                    nmap_txt, xml_path = nmap_service_scan(sub, base_dir / "nmap", full_scan)

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
                        nuclei_base_dir,
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

        # 2) HTTP probe (headers/html snippet)
        log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")        
        with step_timer(f"HTTP probe ({sub})"):
            probe = probe_base(scheme, sub, timeout)
        res["http_probe"] = probe

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

        # 6) Crawl pages
        pages = []
        if do_crawl and not probe.get("error"):
            base = probe.get("final_url") or f"{scheme}://{sub}/"
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"Crawling ({sub})"):
                pages = crawl_site(base, depth=crawl_depth, max_pages=max_pages, timeout=timeout)
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

        # 8) CVE lookup (NVD) from detected services
        res["cves"] = []

        if use_nvd:
            log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            with step_timer(f"CVE lookup {sub}"):
                services = {}

                # 1️⃣ Services détectés via Nmap
                nmap_s = res.get("nmap_structured", {}) or {}
                open_ports = nmap_s.get("open_ports", []) or []

                for p in open_ports:
                    product = p.get("product")
                    version = p.get("version_raw")

                    if product:
                        name = product.lower().strip()

                        clean_version = None

                        if version:
                            # Exemple version_raw: "OpenSSH 10.0p2 Debian 1"
                            version_str = str(version)

                            # On extrait la première version complète incluant suffixe pX
                            match = re.search(r"\d+\.\d+[a-zA-Z0-9\-]*", version_str)
                            if match:
                                clean_version = match.group(0)

                        services[name] = clean_version

                log.info("Detected services for CVE search: %s", services)

                # 2️⃣ Technologies Web détectées (CMS)
                for tech in res.get("cms", []) or []:
                    name = tech.lower().strip()

                    # Nettoyage des préfixes inutiles
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
              full_scan=False , output_dir=None):

    if output_dir:
        base_dir = Path(output_dir)
    else:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        base_dir = Path("results") / f"{target}_{ts}"

    base_dir.mkdir(parents=True, exist_ok=True)

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

            alive_hosts = discover_hosts(hosts)

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
        "reverse_dns": domain if is_ip(target) else None,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "subdomains": {}
    }

    # Multi-thread analysis
    start_time = datetime.now()
    total_cve_found = 0

    with ThreadPoolExecutor(max_workers=max(2, threads)) as ex:
        if subs:
            futures = [
                ex.submit(_analyze_subdomain, s, timeout, crawl_depth, max_pages, do_crawl, use_nvd, base_dir, full_scan)
                for s in subs
            ]
        else:
            futures = [
                ex.submit(_analyze_subdomain, s, timeout, crawl_depth, max_pages, do_crawl, use_nvd, base_dir, full_scan)
                for s in subsip
            ]

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
                        "cves": data.get("cves", []),
                        "risk": data.get("risk"),
                        "httpx": data.get("httpx", []),
                        "nuclei": data.get("nuclei", []),
                        "masscan": data.get("masscan", {}),
                        "nmap_raw": data.get("nmap_raw"),
                        "nmap_structured": data.get("nmap_structured"),
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
                    if xml_path.exists() and xml_path.stat().st_size > 50:

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

                    # ✅ LIVE CVE COUNTER
                    cve_count = len(data.get("cves", []))
                    total_cve_found += cve_count
                    tqdm.write(f"🔎 CVE found for {sub}: {cve_count} (Total: {total_cve_found})")

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
                        "cves": data.get("cves", []),
                        "risk": data.get("risk"),
                        "httpx": data.get("httpx", []),
                        "nuclei": data.get("nuclei", []),
                        "masscan": data.get("masscan", {}),
                        "nmap_raw": data.get("nmap_raw"),
                        "nmap_structured": data.get("nmap_structured"),
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
