"""
Shodan IP lookup — enriches scan results with Shodan intelligence.
Requires SHODAN_API_KEY environment variable or a key passed directly.
Falls back gracefully if the key is absent or the shodan package is missing.
"""
import logging
import os

log = logging.getLogger("recon-audit")

# ── Optional dependency ──────────────────────────────────────────────────────
try:
    import shodan as shodan_lib
    _SHODAN_AVAILABLE = True
except ImportError:
    _SHODAN_AVAILABLE = False


def run_shodan_lookup(ips: list[str], api_key: str | None = None) -> dict:
    """
    Query Shodan for each IP in *ips*.

    Returns a dict keyed by IP:
    {
      "1.2.3.4": {
        "hostnames": [...],
        "org": "...",
        "isp": "...",
        "country": "...",
        "open_ports": [22, 80, ...],
        "vulns": ["CVE-2021-...", ...],
        "tags": [...],
        "banners": [{"port": 22, "banner": "..."}, ...],
        "os": "...",
        "error": None          # or error string
      }
    }
    """
    key = api_key or os.environ.get("SHODAN_API_KEY", "")

    if not _SHODAN_AVAILABLE:
        log.debug("shodan package not installed — skipping Shodan lookup")
        return {}

    if not key:
        log.debug("SHODAN_API_KEY not set — skipping Shodan lookup")
        return {}

    api = shodan_lib.Shodan(key)
    results = {}

    for ip in ips:
        try:
            host = api.host(ip)
            banners = []
            for item in host.get("data", []):
                port = item.get("port")
                banner = item.get("data", "").strip()[:200]
                if port:
                    banners.append({"port": port, "banner": banner})

            results[ip] = {
                "hostnames": host.get("hostnames", []),
                "org": host.get("org", ""),
                "isp": host.get("isp", ""),
                "country": host.get("country_name", ""),
                "city": host.get("city", ""),
                "open_ports": host.get("ports", []),
                "vulns": list(host.get("vulns", {}).keys()),
                "tags": host.get("tags", []),
                "banners": banners,
                "os": host.get("os", ""),
                "last_update": host.get("last_update", ""),
                "error": None,
            }
            log.info("Shodan: %s — %d ports, %d vulns",
                     ip, len(results[ip]["open_ports"]), len(results[ip]["vulns"]))

        except shodan_lib.APIError as e:
            msg = str(e)
            log.warning("Shodan lookup failed for %s: %s", ip, msg)
            results[ip] = {"error": msg}
        except Exception as e:
            log.warning("Shodan unexpected error for %s: %s", ip, e)
            results[ip] = {"error": str(e)}

    return results
