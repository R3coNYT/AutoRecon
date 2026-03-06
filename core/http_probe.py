import requests

def probe_base(scheme: str, host: str, timeout: int):
    url = f"{scheme}://{host}/"
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "ReconAudit/1.0"})
        return {
            "final_url": r.url,
            "status": r.status_code,
            "headers": dict(r.headers),
            "html_snippet": r.text[:4000],
        }
    except Exception as e:
        return {"error": str(e)}
