"""
Subdomain takeover detection.
Checks CNAME chains against known unclaimed service fingerprints.
Source fingerprints: https://github.com/EdOverflow/can-i-take-over-xyz
"""

import logging
import re

import requests

log = logging.getLogger("recon-audit")

TAKEOVER_FINGERPRINTS = [
    {"service": "GitHub Pages",     "cname": ["github.io"],                         "body": ["There isn't a GitHub Pages site here"]},
    {"service": "Amazon S3",        "cname": ["s3.amazonaws.com"],                   "body": ["NoSuchBucket", "The specified bucket does not exist"]},
    {"service": "Heroku",           "cname": ["herokuapp.com", "herokudns.com"],     "body": ["No such app", "no app configured at this hostname"]},
    {"service": "Netlify",          "cname": ["netlify.com", "netlify.app"],         "body": ["Not Found - Request ID"]},
    {"service": "Vercel",           "cname": ["vercel.app", "now.sh"],               "body": ["The deployment could not be found", "404: NOT_FOUND"]},
    {"service": "Shopify",          "cname": ["myshopify.com"],                      "body": ["Sorry, this shop is currently unavailable"]},
    {"service": "Fastly",           "cname": ["fastly.net"],                         "body": ["Fastly error: unknown domain"]},
    {"service": "Ghost",            "cname": ["ghost.io"],                           "body": ["The thing you were looking for is no longer here"]},
    {"service": "Surge.sh",         "cname": ["surge.sh"],                           "body": ["project not found"]},
    {"service": "Azure",            "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"], "body": ["404 Web Site not found"]},
    {"service": "Zendesk",          "cname": ["zendesk.com"],                        "body": ["Help Center Closed"]},
    {"service": "Unbounce",         "cname": ["unbounce.com"],                       "body": ["The requested URL / was not found on this server"]},
    {"service": "Tumblr",           "cname": ["tumblr.com"],                         "body": ["There's nothing here."]},
    {"service": "WordPress.com",    "cname": ["wordpress.com"],                      "body": ["Do you want to register"]},
    {"service": "Pantheon",         "cname": ["pantheonsite.io"],                    "body": ["The gods are wise, but do not know of the site"]},
    {"service": "Kinsta",           "cname": ["kinsta.cloud"],                       "body": ["No Site For Domain"]},
    {"service": "Amazon CloudFront","cname": ["cloudfront.net"],                     "body": ["ERROR: The request could not be satisfied"]},
]


def _get_cname(domain: str) -> str:
    import subprocess
    try:
        proc = subprocess.run(
            ["nslookup", "-type=CNAME", domain],
            capture_output=True, text=True, timeout=10,
        )
        for line in proc.stdout.splitlines():
            if "canonical name" in line.lower():
                m = re.search(r"=\s*(\S+)", line)
                if m:
                    return m.group(1).rstrip(".").lower()
    except Exception:
        pass
    return ""


def _http_body(domain: str) -> str:
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{domain}/", timeout=8,
                allow_redirects=True,
                headers={"User-Agent": "ReconAudit/1.0"},
            )
            return r.text[:3000]
        except Exception:
            pass
    return ""


def check_subdomain_takeover(subdomain: str) -> dict:
    """Check if a subdomain CNAME points to an unclaimed cloud service."""
    cname = _get_cname(subdomain)
    if not cname:
        return {"vulnerable": False, "cname": None}

    for fp in TAKEOVER_FINGERPRINTS:
        cname_match = any(svc in cname for svc in fp["cname"])
        if not cname_match:
            continue

        body = _http_body(subdomain)
        body_match = any(sig in body for sig in fp["body"])

        if body_match:
            return {
                "vulnerable": True,
                "service": fp["service"],
                "cname": cname,
                "evidence": next((sig for sig in fp["body"] if sig in body), ""),
                "warning": f"Subdomain takeover possible via {fp['service']} (CNAME: {cname})",
            }
        # CNAME matches but body not confirmed — suspicious
        return {
            "vulnerable": "potential",
            "service": fp["service"],
            "cname": cname,
            "warning": f"CNAME points to {fp['service']} — verify if claimed ({cname})",
        }

    return {"vulnerable": False, "cname": cname}
