"""Open redirect vulnerability detection.
Tests URL parameters commonly used for redirects.
"""

import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

log = logging.getLogger("recon-audit")

REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirecturi", "redirect_uri",
    "return", "return_url", "returnurl", "next", "goto", "location",
    "dest", "destination", "target", "link", "href", "forward",
    "continue", "rurl", "returl", "checkout_url",
}

PROBE_DOMAIN = "https://evil-recon-probe.com"


def _test_redirect(url: str, param: str, timeout: int) -> dict | None:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return None

    qs[param] = [PROBE_DOMAIN]
    test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    try:
        r = requests.get(
            test_url, timeout=timeout, allow_redirects=False,
            headers={"User-Agent": "ReconAudit/1.0"},
        )
        location = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and PROBE_DOMAIN in location:
            return {
                "url": url,
                "parameter": param,
                "test_url": test_url,
                "redirect_location": location,
                "status_code": r.status_code,
                "severity": "MEDIUM",
                "warning": f"Open redirect via '{param}' parameter",
            }
    except Exception:
        pass
    return None


def scan_open_redirects(pages: list, timeout: int = 8) -> list:
    """Scan crawled pages for open redirect vulnerabilities."""
    findings = []
    tested = set()

    for page in pages:
        url = page.get("url", "")
        if not url:
            continue
        parsed = urlparse(url)
        if not parsed.query:
            continue
        qs = parse_qs(parsed.query)
        for param in qs:
            if param.lower() in REDIRECT_PARAMS:
                key = (parsed.netloc, parsed.path, param)
                if key in tested:
                    continue
                tested.add(key)
                finding = _test_redirect(url, param, timeout)
                if finding:
                    findings.append(finding)

    return findings
