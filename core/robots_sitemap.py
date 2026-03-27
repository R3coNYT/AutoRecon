"""
Parse robots.txt and sitemap.xml to discover hidden paths and seed the crawler.
"""

import re
import logging
import requests
from urllib.parse import urljoin, urlparse

log = logging.getLogger("recon-audit")
UA = {"User-Agent": "ReconAudit/1.0"}


def _fetch(url: str, timeout: int = 8) -> str:
    try:
        r = requests.get(url, timeout=timeout, headers=UA, allow_redirects=True)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""


def parse_robots(base_url: str, timeout: int = 8) -> dict:
    """Fetch and parse robots.txt — returns disallowed/allowed paths and sitemap references."""
    url = urljoin(base_url, "/robots.txt")
    content = _fetch(url, timeout)
    if not content:
        return {"found": False, "disallowed": [], "allowed": [], "sitemaps": []}

    disallowed, allowed, sitemaps = [], [], []
    for line in content.splitlines():
        ln = line.strip()
        if ln.lower().startswith("disallow:"):
            path = ln.split(":", 1)[1].strip()
            if path and path != "/":
                disallowed.append(path)
        elif ln.lower().startswith("allow:"):
            path = ln.split(":", 1)[1].strip()
            if path:
                allowed.append(path)
        elif ln.lower().startswith("sitemap:"):
            sm = ln.split(":", 1)[1].strip()
            if sm:
                sitemaps.append(sm)

    return {
        "found": True,
        "disallowed": disallowed[:60],
        "allowed": allowed[:60],
        "sitemaps": sitemaps,
        "raw": content[:600],
    }


def parse_sitemap(base_url: str, timeout: int = 8) -> list:
    """Fetch /sitemap.xml and extract all URLs. Follows sitemap index entries."""
    url = urljoin(base_url, "/sitemap.xml")
    content = _fetch(url, timeout)
    if not content:
        return []

    # Follow sitemap index (up to 5 sub-sitemaps)
    sub_sitemaps = re.findall(
        r"<loc>\s*(https?://[^<]+sitemap[^<]*\.xml[^<]*)\s*</loc>",
        content, re.IGNORECASE,
    )
    for sm_url in sub_sitemaps[:5]:
        sub = _fetch(sm_url.strip(), timeout)
        if sub:
            content += sub

    urls = []
    for m in re.finditer(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", content, re.IGNORECASE):
        urls.append(m.group(1).strip())

    return urls[:300]


def get_seed_urls(base_url: str, timeout: int = 8) -> dict:
    """
    Return seed URLs from robots.txt (disallowed paths = interesting targets)
    and sitemap.xml to supplement the crawler.
    """
    robots = parse_robots(base_url, timeout)
    sitemap_urls = parse_sitemap(base_url, timeout)

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    disallowed_urls = [urljoin(origin, p) for p in robots.get("disallowed", [])]

    seed = list(set(sitemap_urls + disallowed_urls))[:150]
    return {
        "robots": robots,
        "sitemap_urls": sitemap_urls,
        "disallowed_urls": disallowed_urls,
        "seed_urls": seed,
    }
