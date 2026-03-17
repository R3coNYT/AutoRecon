import requests

def lookup_nvd(keyword: str, timeout: int = 30, limit: int = 200):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": limit}
    try:
        r = requests.get(url, params=params, timeout=timeout)
        data = r.json()
    except Exception:
        return []

    out = []
    for item in data.get("vulnerabilities", [])[:limit]:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descs = cve.get("descriptions", [])
        desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "")

        # CVSS (v3.1 preferred)
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss = {
                    "version": key,
                    "score": m.get("cvssData", {}).get("baseScore"),
                    "severity": m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity"),
                    "vector": m.get("cvssData", {}).get("vectorString")
                }
                break

        out.append({"id": cve_id, "cvss": cvss, "summary": desc[:240]})
    return out
