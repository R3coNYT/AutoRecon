"""Cookie security flag analysis.
Checks HttpOnly, Secure, SameSite for each Set-Cookie header.
"""


def analyze_cookies(headers: dict) -> list:
    """
    Parse Set-Cookie headers and audit security flags.
    Returns list of cookie findings.
    """
    if not headers:
        return []

    raw_cookies = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            if isinstance(v, list):
                raw_cookies.extend(v)
            else:
                raw_cookies.append(v)

    findings = []
    for cookie_str in raw_cookies:
        parts = [p.strip() for p in cookie_str.split(";")]
        name = parts[0].split("=")[0].strip() if parts else "unknown"
        lower_parts = [p.lower() for p in parts]

        missing_flags = []
        risks = []

        if "httponly" not in lower_parts:
            missing_flags.append("HttpOnly")
            risks.append("XSS can steal this cookie via document.cookie")

        if "secure" not in lower_parts:
            missing_flags.append("Secure")
            risks.append("Cookie transmitted over HTTP — interception / MITM possible")

        has_samesite = any(p.startswith("samesite") for p in lower_parts)
        if not has_samesite:
            missing_flags.append("SameSite")
            risks.append("CSRF attack possible (no SameSite policy)")
        else:
            samesite_val = next((p for p in lower_parts if p.startswith("samesite")), "")
            if "samesite=none" in samesite_val and "secure" not in lower_parts:
                risks.append("SameSite=None without Secure flag — invalid configuration")

        if missing_flags:
            findings.append({
                "name": name,
                "raw": cookie_str[:200],
                "missing_flags": missing_flags,
                "risks": risks,
                "severity": (
                    "HIGH" if "HttpOnly" in missing_flags and "Secure" in missing_flags
                    else "MEDIUM"
                ),
            })

    return findings
