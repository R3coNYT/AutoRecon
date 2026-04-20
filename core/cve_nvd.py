"""
NVD (National Vulnerability Database) API v2.0 wrapper.
Mirrors the CVE extraction logic used in Centralized so that CVE IDs,
CVSS scores and severity labels match between both tools.

Rate limits:
  Without API key : 5 requests / 30 s → ~0.7 s between requests
  With API key    : 50 requests / 30 s → ~0.1 s between requests
Set NVD_API_KEY in the environment (or .env) to raise the limit.
"""

import os
import re
import time
import requests

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_last_request_time: float = 0.0


def _throttle() -> None:
    """Enforce inter-request delay to stay within NVD rate limits."""
    global _last_request_time
    api_key = os.getenv("NVD_API_KEY", "")
    delay = 0.1 if api_key else 0.7
    elapsed = time.monotonic() - _last_request_time
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _last_request_time = time.monotonic()


def _nvd_headers() -> dict:
    api_key = os.getenv("NVD_API_KEY", "")
    h = {"User-Agent": "AutoRecon/1.0"}
    if api_key:
        h["apiKey"] = api_key
    return h


def _score_to_severity(score) -> str:
    if score is None:
        return "UNKNOWN"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _extract_cve(cve: dict) -> dict | None:
    """
    Convert a raw NVD CVE object into a flat dict.
    Field names and logic match Centralized's cve_service._extract_cve() so
    that CVE IDs, scores and severities are identical between both tools.
    """
    if not cve:
        return None

    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    desc_en = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    severity   = "UNKNOWN"
    cvss_score = None
    cvss_vector = None

    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            m         = metric_list[0]
            cvss_data = m.get("cvssData", {})
            cvss_score  = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            severity = (
                m.get("baseSeverity")
                or cvss_data.get("baseSeverity")
                or _score_to_severity(cvss_score)
            )
            break

    refs = cve.get("references", [])
    all_ref_urls = list(dict.fromkeys(r.get("url", "") for r in refs if r.get("url")))

    PATCH_TAGS = {"Patch", "Fix", "Mitigation", "Vendor Advisory", "Third Party Advisory"}
    patch_refs = list(dict.fromkeys(
        r["url"] for r in refs
        if r.get("url") and PATCH_TAGS.intersection(set(r.get("tags", [])))
    ))

    weaknesses: list[str] = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if d.get("lang") == "en" and val.startswith("CWE-") and val not in weaknesses:
                weaknesses.append(val)

    exploited_in_wild = "cisaExploitAdd" in cve
    cisa_remediation  = cve.get("cisaRequiredAction")

    return {
        "cve_id":           cve_id,
        # 'id' kept for backward compatibility with any callers that read cve["id"]
        "id":               cve_id,
        "description":      desc_en,
        # 'summary' kept for backward compatibility
        "summary":          desc_en[:240],
        "severity":         severity.upper() if severity else "UNKNOWN",
        "cvss_score":       cvss_score,
        "cvss_vector":      cvss_vector,
        "references":       all_ref_urls[:10],
        "patch_refs":       patch_refs[:8],
        "patch_available":  len(patch_refs) > 0,
        "weaknesses":       weaknesses,
        "exploited_in_wild": exploited_in_wild,
        "cisa_remediation": cisa_remediation,
        "published":        cve.get("published", ""),
        "last_modified":    cve.get("lastModified", ""),
        "vuln_status":      cve.get("vulnStatus", ""),
    }


def lookup_nvd(keyword: str, timeout: int = 30, limit: int = 200) -> list[dict]:
    """
    Search NVD for CVEs matching *keyword* (e.g. 'OpenSSH 8.4').
    Returns a list of flat CVE dicts — same structure as Centralized.
    """
    if not keyword or len(keyword.strip()) < 3:
        return []

    try:
        _throttle()
        r = requests.get(
            _NVD_URL,
            params={"keywordSearch": keyword, "resultsPerPage": limit},
            headers=_nvd_headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []

    out: list[dict] = []
    for item in data.get("vulnerabilities", [])[:limit]:
        extracted = _extract_cve(item.get("cve", {}))
        if extracted:
            out.append(extracted)
    return out
