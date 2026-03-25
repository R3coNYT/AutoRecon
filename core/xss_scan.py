"""
XSS (Cross-Site Scripting) scanner.

Strategy
--------
For each crawled page:
  1. Collect all URL query parameters.
  2. Collect all HTML form fields (input / textarea / select).
  3. Inject a unique sentinel payload into each parameter/field one at a time.
  4. Check whether the payload is reflected unencoded in the response body.

This is a *reflected* XSS check — it does NOT execute JavaScript.  It only
detects raw reflection that a real browser would execute.  Stored / DOM-based
XSS is out of scope for a passive-style recon tool.

No external tools required — pure Python / requests.
"""

from __future__ import annotations

import re
import logging
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from bs4 import BeautifulSoup

log = logging.getLogger("recon-audit")

# Sentinel string that is clearly not a normal value and easy to search for.
# Angle brackets are the minimum required to test raw reflection.
_SENTINEL = "<xss-recon-probe/>"

# Simple heuristic payloads — only the first injectable format is tried per
# parameter.  We stop as soon as we get a hit so we don't flood the server.
_PAYLOADS = [
    "<xss-recon-probe/>",
    '"><xss-recon-probe/>',
    "'><xss-recon-probe/>",
    "<ScRiPt>xss-recon-probe</ScRiPt>",
]


def _is_reflected(response_text: str) -> bool:
    """Return True if any payload fragment appears unencoded in the response."""
    t = response_text
    return (
        "<xss-recon-probe" in t
        or "xss-recon-probe</script>" in t.lower()
    )


def _test_url_params(
    url: str,
    session: requests.Session,
    timeout: int,
) -> list[dict]:
    """Inject payloads into each query-string parameter of *url*."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    findings = []
    for param in list(params.keys()):
        for payload in _PAYLOADS:
            injected = dict(params)
            injected[param] = payload
            test_url = parsed._replace(query=urlencode(injected, doseq=True)).geturl()
            try:
                r = session.get(
                    test_url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "ReconAudit/1.0"},
                )
                if _is_reflected(r.text):
                    findings.append({
                        "type":      "reflected_xss",
                        "url":       url,
                        "method":    "GET",
                        "parameter": param,
                        "payload":   payload,
                        "evidence":  f"Payload reflected in response body (HTTP {r.status_code})",
                    })
                    break  # one hit per parameter is enough
            except Exception:
                pass

    return findings


def _test_form(
    page_url: str,
    form,
    session: requests.Session,
    timeout: int,
) -> list[dict]:
    """Inject payloads into each text field of an HTML <form>."""
    action = form.get("action") or page_url
    action = urljoin(page_url, action)
    method = (form.get("method") or "get").strip().lower()

    fields: dict[str, str] = {}
    for inp in form.find_all(["input", "textarea", "select"]):
        name = inp.get("name")
        if not name:
            continue
        itype = inp.get("type", "text").lower()
        if itype in ("submit", "button", "image", "reset", "hidden", "file"):
            # Keep hidden fields at their default value so the form validates
            if itype == "hidden":
                fields[name] = inp.get("value", "")
            continue
        fields[name] = inp.get("value", "")

    if not fields:
        return []

    # Only probe text-type fields
    text_fields = [
        k for k, _v in fields.items()
        if not any(
            f.get("type", "text").lower() in ("hidden",)
            for f in form.find_all(["input"])
            if f.get("name") == k
        )
    ]

    findings = []
    for field in text_fields:
        for payload in _PAYLOADS:
            data = dict(fields)
            data[field] = payload
            try:
                if method == "post":
                    r = session.post(
                        action, data=data, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": "ReconAudit/1.0"},
                    )
                else:
                    r = session.get(
                        action, params=data, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": "ReconAudit/1.0"},
                    )
                if _is_reflected(r.text):
                    findings.append({
                        "type":      "reflected_xss",
                        "url":       page_url,
                        "form_action": action,
                        "method":    method.upper(),
                        "parameter": field,
                        "payload":   payload,
                        "evidence":  f"Payload reflected in response body (HTTP {r.status_code})",
                    })
                    break
            except Exception:
                pass

    return findings


def scan_xss(pages: list[dict], timeout: int = 7) -> list[dict]:
    """
    Run reflected-XSS probing against all crawled pages.

    Args:
        pages:   List of page dicts from crawl_site() — each has at least {"url": ...}.
        timeout: Per-request timeout in seconds.

    Returns:
        List of finding dicts with keys:
            type, url, method, parameter, payload, evidence
            (+ form_action when the injection was via a form POST/GET)
    """
    findings: list[dict] = []

    with requests.Session() as session:
        for page in pages:
            url = page.get("url", "")
            if not url:
                continue

            # 1. Query-string parameter injection
            findings.extend(_test_url_params(url, session, timeout))

            # 2. Form field injection — re-fetch the page to get its forms
            try:
                r = session.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "ReconAudit/1.0"},
                )
                soup = BeautifulSoup(r.text, "html.parser")
                for form in soup.find_all("form"):
                    findings.extend(_test_form(url, form, session, timeout))
            except Exception:
                pass

    # Deduplicate by (url, parameter, method)
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in findings:
        key = (f.get("url"), f.get("parameter"), f.get("method"))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    if deduped:
        log.info("XSS scanner found %d potential reflected XSS findings", len(deduped))
    return deduped
