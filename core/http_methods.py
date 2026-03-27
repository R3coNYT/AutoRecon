"""HTTP dangerous method testing (PUT, DELETE, TRACE, TRACK)."""

import logging
import requests
from urllib.parse import urlparse

log = logging.getLogger("recon-audit")

METHOD_RISKS = {
    "PUT":     "arbitrary file upload possible",
    "DELETE":  "file deletion possible",
    "TRACE":   "Cross-Site Tracing (XST) — credential theft via XSS",
    "TRACK":   "Cross-Site Tracing variant",
    "CONNECT": "proxy abuse possible",
}


def test_http_methods(url: str, timeout: int = 8) -> dict:
    """Test which dangerous HTTP methods are accepted at a URL."""
    findings = []

    # Check Allow header via OPTIONS
    try:
        r = requests.options(url, timeout=timeout, headers={"User-Agent": "ReconAudit/1.0"})
        allow_header = r.headers.get("Allow", r.headers.get("allow", ""))
        if allow_header:
            for method in METHOD_RISKS:
                if method in allow_header.upper():
                    findings.append({
                        "url": url,
                        "method": method,
                        "detection": "Allow header",
                        "severity": "HIGH" if method in ("PUT", "DELETE") else "MEDIUM",
                        "warning": f"{method} declared in Allow header — {METHOD_RISKS[method]}",
                    })
    except Exception:
        pass

    # Actively probe TRACE and PUT (safe probes)
    for method in ["TRACE", "PUT"]:
        if any(f["method"] == method for f in findings):
            continue  # Already found via OPTIONS
        try:
            r = requests.request(
                method, url, timeout=timeout,
                headers={"User-Agent": "ReconAudit/1.0"},
                data=b"recon-probe" if method == "PUT" else None,
                allow_redirects=False,
            )
            if r.status_code not in (405, 501, 400, 403, 404):
                findings.append({
                    "url": url,
                    "method": method,
                    "status_code": r.status_code,
                    "detection": "active probe",
                    "severity": "HIGH" if method == "PUT" else "MEDIUM",
                    "warning": f"{method} returned {r.status_code} — {METHOD_RISKS[method]}",
                })
        except Exception:
            pass

    return {"url": url, "findings": findings, "vulnerable": bool(findings)}


def run_http_method_tests(pages: list, timeout: int = 8) -> list:
    """Run HTTP method tests on unique origins from crawled pages."""
    checked = set()
    all_findings = []

    for page in pages[:20]:
        url = page.get("url", "")
        if not url:
            continue
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}/"
        if origin in checked:
            continue
        checked.add(origin)

        result = test_http_methods(origin, timeout)
        all_findings.extend(result.get("findings", []))

    return all_findings
