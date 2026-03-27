"""Analyse des security headers HTTP pour détecter les configurations manquantes ou risquées."""

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "short": "CSP",
        "risk": "HIGH",
        "desc": "Missing Content-Security-Policy — XSS mitigation absent.",
    },
    "Strict-Transport-Security": {
        "short": "HSTS",
        "risk": "MEDIUM",
        "desc": "Missing HSTS — HTTP downgrade / MITM attacks possible.",
    },
    "X-Frame-Options": {
        "short": "XFO",
        "risk": "MEDIUM",
        "desc": "Missing X-Frame-Options — clickjacking possible.",
    },
    "X-Content-Type-Options": {
        "short": "XCTO",
        "risk": "LOW",
        "desc": "Missing X-Content-Type-Options — MIME-sniffing possible.",
    },
    "Referrer-Policy": {
        "short": "RP",
        "risk": "LOW",
        "desc": "Missing Referrer-Policy — sensitive URL leakage possible.",
    },
    "Permissions-Policy": {
        "short": "PP",
        "risk": "LOW",
        "desc": "Missing Permissions-Policy — browser features unrestricted.",
    },
}

# Headers that reveal server info (information disclosure)
LEAKY_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator",
]


def analyze_security_headers(headers: dict) -> dict:
    """
    Analyze HTTP response headers for security misconfigurations.

    Returns:
        missing: list of {header, short, risk, desc}
        present: list of present security header names
        leaky: list of {header, value}
        score: int 0–100 (higher = more secure)
    """
    if not headers:
        return {"missing": [], "present": [], "leaky": [], "score": 0}

    headers_lower = {k.lower(): v for k, v in headers.items()}
    missing = []
    present = []

    for header, meta in SECURITY_HEADERS.items():
        if header.lower() in headers_lower:
            present.append(header)
        else:
            missing.append({
                "header": header,
                "short": meta["short"],
                "risk": meta["risk"],
                "desc": meta["desc"],
            })

    leaky = []
    for lh in LEAKY_HEADERS:
        if lh.lower() in headers_lower:
            leaky.append({"header": lh, "value": headers_lower[lh.lower()]})

    score = 100
    for m in missing:
        if m["risk"] == "HIGH":
            score -= 15
        elif m["risk"] == "MEDIUM":
            score -= 10
        else:
            score -= 5
    score -= len(leaky) * 3
    score = max(0, score)

    return {
        "missing": missing,
        "present": present,
        "leaky": leaky,
        "score": score,
    }
