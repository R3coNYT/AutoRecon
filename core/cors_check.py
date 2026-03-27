"""CORS misconfiguration detection.
Sends crafted Origin headers and checks if the server reflects them.
"""

import logging
import requests
from urllib.parse import urlparse

log = logging.getLogger("recon-audit")

PROBE_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


def check_cors(url: str, timeout: int = 8) -> dict:
    """Test CORS policy for a URL. Returns misconfigurations found."""
    findings = []
    for origin in PROBE_ORIGINS:
        try:
            r = requests.get(
                url,
                headers={"User-Agent": "ReconAudit/1.0", "Origin": origin},
                timeout=timeout,
                allow_redirects=True,
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == origin or acao == "*":
                with_creds = acao == origin and acac.lower() == "true"
                findings.append({
                    "url": url,
                    "origin_sent": origin,
                    "acao": acao,
                    "credentials_allowed": with_creds,
                    "severity": "HIGH" if with_creds else "MEDIUM",
                    "warning": (
                        "CORS reflects arbitrary origin WITH credentials — full cross-origin data theft possible"
                        if with_creds
                        else f"CORS allows arbitrary origin '{acao}'"
                    ),
                })
                break  # One finding per URL is enough
        except Exception as e:
            log.debug("CORS check error on %s: %s", url, e)

    return {
        "checked": True,
        "findings": findings,
        "vulnerable": len(findings) > 0,
    }


def run_cors_checks(pages: list, timeout: int = 8) -> list:
    """Run CORS checks on unique origins from crawled pages."""
    checked_origins = set()
    all_findings = []

    for page in pages[:30]:
        url = page.get("url", "")
        if not url:
            continue
        origin = urlparse(url).netloc
        if origin in checked_origins:
            continue
        checked_origins.add(origin)

        result = check_cors(url, timeout)
        all_findings.extend(result.get("findings", []))

    return all_findings
