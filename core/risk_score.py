import re

def extract_version(version_raw):
    if not version_raw:
        return None

    match = re.search(r"\d+(\.\d+)+", version_raw)
    return match.group(0) if match else None

def compute_risk_score(sub_report: dict):
    score = 0
    reasons = []
    potential_flag = False

    # =========================
    # 1) Port analysis
    # =========================
    nmap_s = sub_report.get("nmap_structured", {}) or {}
    open_ports = nmap_s.get("open_ports", []) or []
    open_port_nums = {p.get("port") for p in open_ports if p.get("port")}

    sensitive = {22, 3389, 445, 21, 23, 3306, 5432, 6379, 27017, 1433, 5900}
    hit = sorted(open_port_nums.intersection(sensitive))
    if hit:
        score += 25
        reasons.append(f"Sensitive ports exposed: {hit}")

    for p in open_ports:
        product = p.get("product")
        version = extract_version(p.get("version_raw"))
        if product and not version:
            potential_flag = True
            reasons.append(f"Version not confirmed for service '{product}'")

    # =========================
    # 2) TLS
    # =========================
    tls = sub_report.get("tls", {}) or {}
    if tls.get("cert_expired") is True:
        score += 25
        reasons.append("TLS certificate expired")

    # =========================
    # 3) CVE severity
    # =========================
    cves = sub_report.get("cves", []) or []
    max_cvss = 0.0
    critical = 0
    high = 0

    for v in cves:
        cvss = (v.get("cvss") or {})
        s = cvss.get("score")
        try:
            s = float(s)
            if s > max_cvss:
                max_cvss = s
            if s >= 9.0:
                critical += 1
            elif s >= 7.0:
                high += 1
        except Exception:
            pass

    if critical:
        score += 30
        reasons.append(f"{critical} CRITICAL CVEs (max CVSS={max_cvss})")
    elif high:
        score += 15
        reasons.append(f"{high} HIGH CVEs (max CVSS={max_cvss})")

    # =========================
    # 4) WAF (per service, not global)
    # =========================
    if sub_report.get("waf"):
        score -= 5
        reasons.append("WAF hints detected (minor risk reduction)")

    # =========================
    # 5) Security headers
    # =========================
    sec_hdrs = sub_report.get("security_headers", {}) or {}
    missing_hdrs = sec_hdrs.get("missing", []) or []
    high_missing = [m for m in missing_hdrs if m.get("risk") == "HIGH"]
    med_missing  = [m for m in missing_hdrs if m.get("risk") == "MEDIUM"]
    if high_missing:
        score += 10
        reasons.append(f"Critical security headers missing: {[m['short'] for m in high_missing]}")
    if med_missing:
        score += 5
        reasons.append(f"Security headers missing: {[m['short'] for m in med_missing]}")

    # =========================
    # 6) Cookie security
    # =========================
    cookies = sub_report.get("cookies", []) or []
    high_cookie = [c for c in cookies if c.get("severity") == "HIGH"]
    if high_cookie:
        score += 10
        reasons.append(f"{len(high_cookie)} cookie(s) missing HttpOnly+Secure flags")

    # =========================
    # 7) CORS misconfig
    # =========================
    cors = sub_report.get("cors_findings", []) or []
    high_cors = [c for c in cors if c.get("severity") == "HIGH"]
    if high_cors:
        score += 20
        reasons.append("CORS misconfiguration with credentials — cross-origin data theft possible")
    elif cors:
        score += 10
        reasons.append("CORS misconfiguration detected")

    # =========================
    # 8) Service-specific vulnerabilities
    # =========================
    svc = sub_report.get("service_checks", {}) or {}
    if svc.get("ftp", {}).get("anonymous_login"):
        score += 20
        reasons.append("FTP anonymous login allowed")
    if svc.get("redis", {}).get("unauthenticated"):
        score += 25
        reasons.append("Redis accessible without authentication (critical)")
    if svc.get("mongodb", {}).get("unauthenticated"):
        score += 25
        reasons.append("MongoDB accessible without authentication (critical)")
    if svc.get("smtp", {}).get("open_relay"):
        score += 15
        reasons.append("SMTP open relay detected")

    # =========================
    # 9) Subdomain takeover
    # =========================
    takeover = sub_report.get("takeover", {}) or {}
    if takeover.get("vulnerable") is True:
        score += 30
        reasons.append(f"Subdomain takeover possible via {takeover.get('service')}")
    elif takeover.get("vulnerable") == "potential":
        score += 10
        potential_flag = True
        reasons.append(f"Potential takeover — CNAME points to {takeover.get('service')}")

    # =========================
    # 10) DNS misconfigurations
    # =========================
    dns = sub_report.get("dns_audit", {}) or {}
    zt = dns.get("zone_transfer", {}) or {}
    if zt.get("vulnerable"):
        score += 20
        reasons.append("DNS zone transfer (AXFR) allowed")
    email_sec = dns.get("email_security", {}) or {}
    if not email_sec.get("spf", {}).get("present"):
        score += 5
        reasons.append("No SPF record — email spoofing possible")
    if not email_sec.get("dmarc", {}).get("present"):
        score += 5
        reasons.append("No DMARC record — email spoofing possible")

    # =========================
    # 11) HTTP dangerous methods
    # =========================
    http_methods = sub_report.get("http_methods", []) or []
    critical_methods = [m for m in http_methods if m.get("severity") == "HIGH"]
    if critical_methods:
        score += 15
        reasons.append(f"Dangerous HTTP methods: {[m['method'] for m in critical_methods]}")

    # =========================
    # 12) Open redirects / JS secrets
    # =========================
    if sub_report.get("open_redirects"):
        score += 8
        reasons.append(f"{len(sub_report['open_redirects'])} open redirect(s) detected")
    js_secs = sub_report.get("js_secrets", []) or []
    high_secrets = [s for s in js_secs if s.get("type") in ("AWS Access Key", "Private Key", "GitHub Token", "Stripe Key")]
    if high_secrets:
        score += 25
        reasons.append(f"Sensitive secrets exposed in JS: {[s['type'] for s in high_secrets[:3]]}")
    elif js_secs:
        score += 10
        reasons.append(f"{len(js_secs)} potential secret(s) found in JS files")

    # =========================
    # 13) Shodan CVEs / exposed services
    # =========================
    shodan = sub_report.get("shodan", {}) or {}
    for ip_data in shodan.values():
        if isinstance(ip_data, dict):
            vulns = ip_data.get("vulns", []) or []
            if vulns:
                score += min(30, len(vulns) * 5)
                reasons.append(f"Shodan: {len(vulns)} CVE(s) for this IP: {vulns[:3]}")

    # =========================
    # 14) Cloud buckets
    # =========================
    buckets = sub_report.get("cloud_buckets", []) or []
    public_buckets = [b for b in buckets if b.get("public")]
    if public_buckets:
        score += 25
        reasons.append(f"{len(public_buckets)} publicly readable cloud storage bucket(s)")
    elif buckets:
        score += 8
        reasons.append(f"{len(buckets)} cloud storage bucket(s) exposed (access denied, but exists)")

    # =========================
    # 15) JWT vulnerabilities
    # =========================
    jwt_findings = sub_report.get("jwt_findings", []) or []
    high_jwt = [j for j in jwt_findings if j.get("severity") == "HIGH"]
    if high_jwt:
        score += 20
        issues_summary = [i for j in high_jwt for i in j.get("issues", [])]
        reasons.append(f"JWT vulnerability: {issues_summary[0] if issues_summary else 'weak/insecure token'}")
    elif jwt_findings:
        score += 5
        reasons.append(f"{len(jwt_findings)} JWT token(s) found — review manually")

    # =========================
    # 16) DOM XSS
    # =========================
    dom_xss = sub_report.get("dom_xss", []) or []
    if dom_xss:
        score += 20
        reasons.append(f"{len(dom_xss)} DOM XSS finding(s) confirmed via Playwright")

    # =========================
    # Final score & classification
    # =========================
    score = max(0, min(100, score))

    if potential_flag and score < 60:
        level = "POTENTIAL"
    else:
        level = "LOW" if score < 25 else "MEDIUM" if score < 60 else "HIGH"

    return {"score": score, "level": level, "reasons": reasons, "version_unknown": potential_flag}
