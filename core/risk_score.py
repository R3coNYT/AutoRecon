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
    # 1️⃣ Analyse des ports
    # =========================
    nmap_s = sub_report.get("nmap_structured", {}) or {}
    open_ports = nmap_s.get("open_ports", []) or []

    open_port_nums = {p.get("port") for p in open_ports if p.get("port")}

    sensitive = {22, 3389, 445, 21, 23, 3306, 5432, 6379}
    hit = sorted(open_port_nums.intersection(sensitive))
    if hit:
        score += 25
        reasons.append(f"Sensitive ports exposed: {hit}")

    # 🔎 Détection version manquante
    for p in open_ports:
        product = p.get("product")
        version = extract_version(p.get("version_raw"))

        if product and not version:
            potential_flag = True
            reasons.append(f"Version not confirmed for service '{product}'")

    # =========================
    # 2️⃣ TLS
    # =========================
    tls = sub_report.get("tls", {}) or {}
    if tls.get("cert_expired") is True:
        score += 25
        reasons.append("TLS certificate expired")

    # =========================
    # 3️⃣ CVE severity
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
    # 4️⃣ WAF bonus
    # =========================
    if sub_report.get("waf"):
        score -= 5
        reasons.append("WAF hints detected (minor risk reduction)")

    score = max(0, min(100, score))

    # =========================
    # 5️⃣ Classification finale
    # =========================
    if potential_flag and score < 60:
        level = "POTENTIAL"
    else:
        level = "LOW" if score < 25 else "MEDIUM" if score < 60 else "HIGH"

    return {"score": score, "level": level, "reasons": reasons, "version_unknown": potential_flag}
