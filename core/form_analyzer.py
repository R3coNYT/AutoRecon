from bs4 import BeautifulSoup
import requests

def detect_login_forms(pages, timeout: int):
    hits = []
    for p in pages:
        url = p["url"]
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": "ReconAudit/1.0"})
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                inputs = form.find_all("input")
                types = [i.get("type", "").lower() for i in inputs]
                names = [i.get("name", "").lower() for i in inputs]
                if "password" in types or any("pass" in n for n in names):
                    hits.append({
                        "page": url,
                        "action": form.get("action", ""),
                        "method": (form.get("method", "get") or "get").lower()
                    })
                    break
        except Exception:
            continue
    return hits
