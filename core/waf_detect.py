def detect_waf(headers: dict, body_snippet: str):
    h = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    b = (body_snippet or "").lower()

    waf_hits = []

    # Common header hints
    if "cf-ray" in h or "cloudflare" in h.get("server", ""):
        waf_hits.append("Cloudflare (possible)")
    if "akamai" in h.get("server", "") or "akamai" in h.get("x-akamai-transformed", ""):
        waf_hits.append("Akamai (possible)")
    if "imperva" in h.get("set-cookie", "") or "incapsula" in h.get("set-cookie", ""):
        waf_hits.append("Imperva/Incapsula (possible)")
    if "sucuri" in h.get("server", "") or "sucuri" in h.get("x-sucuri-id", ""):
        waf_hits.append("Sucuri (possible)")
    if "f5" in h.get("set-cookie", ""):
        waf_hits.append("F5 (possible)")

    # Common block page hints
    if "access denied" in b or "request blocked" in b or "waf" in b:
        waf_hits.append("Generic WAF block page hint")

    return sorted(set(waf_hits))
