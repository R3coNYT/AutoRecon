"""
Extract potential secrets from JavaScript files found during crawling.
Searches for API keys, tokens, hardcoded credentials using known regex patterns.
"""

import re
import logging
import requests
from urllib.parse import urljoin, urlparse

log = logging.getLogger("recon-audit")
UA = {"User-Agent": "ReconAudit/1.0"}

SECRET_PATTERNS = [
    ("AWS Access Key",      r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",      r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API Key",      r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth",        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("GitHub Token",        r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}"),
    ("Bearer Token",        r"(?i)bearer\s+[a-zA-Z0-9\-_=]{20,}"),
    ("Private Key",         r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("Generic API Key",     r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9\-_]{16,64})"),
    ("Generic Password",    r"(?i)(password|passwd|pwd)['\"\s]*[:=]['\"\s]*['\"]([^'\"]{8,64})['\"]"),
    ("Generic Token",       r"(?i)(token|secret|auth)['\"\s]*[:=]['\"\s]*['\"]([a-zA-Z0-9\-_\.]{16,128})['\"]"),
    ("Stripe Key",          r"(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}"),
    ("Slack Token",         r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}"),
    ("Twilio SID",          r"AC[a-z0-9]{32}"),
    ("Internal Endpoint",   r"(?:https?://)?(?:internal|admin|dev|staging|localhost|127\.0\.0\.\d|192\.168\.\d+\.\d|10\.\d+\.\d+\.\d)"),
]

SKIP_PATTERNS = [
    re.compile(r"example\.com", re.IGNORECASE),
    re.compile(r"placeholder", re.IGNORECASE),
    re.compile(r"lorem\s+ipsum", re.IGNORECASE),
    re.compile(r"YOUR_API_KEY", re.IGNORECASE),
    re.compile(r"INSERT_KEY_HERE", re.IGNORECASE),
    re.compile(r"<[^>]+>"),  # HTML tags embedded in match
]


def _fetch_js_urls_from_page(url: str, timeout: int) -> list:
    """Fetch a page and collect same-origin <script src=...> URLs."""
    try:
        from bs4 import BeautifulSoup
        r = requests.get(url, timeout=timeout, headers=UA, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        origin = urlparse(url).netloc
        return [
            urljoin(url, tag["src"])
            for tag in soup.find_all("script", src=True)
            if tag.get("src") and urlparse(urljoin(url, tag["src"])).netloc == origin
        ]
    except Exception:
        return []


def _scan_content(content: str, source_url: str) -> list:
    findings = []
    for name, pattern in SECRET_PATTERNS:
        try:
            for m in re.finditer(pattern, content):
                match_str = m.group(0)
                if any(fp.search(match_str) for fp in SKIP_PATTERNS):
                    continue
                findings.append({
                    "type": name,
                    "match": match_str[:150],
                    "source": source_url,
                    "context": content[max(0, m.start() - 30):m.end() + 30].strip()[:200],
                })
        except Exception:
            pass
    return findings


def scan_js_secrets(pages: list, timeout: int = 8) -> list:
    """
    Scan JS files linked from crawled pages for secrets.
    Returns deduplicated list of findings.
    """
    scanned = set()
    all_findings = []

    for page in pages[:50]:
        page_url = page.get("url", "")
        if not page_url:
            continue
        for js_url in _fetch_js_urls_from_page(page_url, timeout)[:20]:
            if js_url in scanned:
                continue
            scanned.add(js_url)
            try:
                r = requests.get(js_url, timeout=timeout, headers=UA)
                if r.status_code == 200 and len(r.text) < 2_000_000:
                    all_findings.extend(_scan_content(r.text, js_url))
            except Exception:
                pass

    # Deduplicate by (type, match prefix)
    seen = set()
    unique = []
    for f in all_findings:
        key = (f["type"], f["match"][:50])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
