from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import requests
from collections import deque

def crawl_site(base_url: str, depth: int, max_pages: int, timeout: int):
    visited = set()
    pages = []
    q = deque([(base_url, 0)])

    base_netloc = urlparse(base_url).netloc

    while q and len(pages) < max_pages:
        url, d = q.popleft()
        if url in visited or d > depth:
            continue
        visited.add(url)

        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "ReconAudit/1.0"})
            ct = r.headers.get("Content-Type", "")
            if "text/html" not in ct:
                continue

            pages.append({"url": r.url, "status": r.status_code, "len": len(r.text)})

            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                nxt = urljoin(r.url, a["href"])
                p = urlparse(nxt)
                if p.scheme in ("http", "https") and p.netloc == base_netloc:
                    q.append((nxt.split("#")[0], d + 1))

        except Exception:
            continue

    return pages
