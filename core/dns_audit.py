"""
DNS security audit:
- Zone transfer (AXFR)
- SPF / DMARC / DKIM
- Wildcard DNS
"""

import socket
import subprocess
import logging
import re
import random
import string
import ipaddress

log = logging.getLogger("recon-audit")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _nslookup(query_type: str, domain: str, server: str = "") -> str:
    cmd = ["nslookup", f"-type={query_type}", domain]
    if server:
        cmd.append(server)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        return proc.stdout + proc.stderr
    except Exception:
        return ""


def _get_nameservers(domain: str) -> list:
    output = _nslookup("NS", domain)
    ns_list = []
    for line in output.splitlines():
        m = re.search(r"nameserver\s*=\s*(\S+)", line, re.IGNORECASE)
        if m:
            ns = m.group(1).rstrip(".")
            if ns:
                ns_list.append(ns)
    return ns_list


def check_zone_transfer(domain: str) -> dict:
    ns_list = _get_nameservers(domain)
    results = []
    for ns in ns_list:
        output = _nslookup("AXFR", domain, ns)
        # Successful AXFR returns many records (SOA, A, MX, etc.)
        record_count = len(re.findall(r"\bA\b|\bMX\b|\bCNAME\b|\bNS\b", output))
        vulnerable = record_count > 5
        results.append({
            "nameserver": ns,
            "vulnerable": vulnerable,
            "evidence": output[:400] if vulnerable else "",
        })
    return {
        "nameservers": ns_list,
        "axfr_results": results,
        "vulnerable": any(r.get("vulnerable") for r in results),
        "warning": "DNS zone transfer (AXFR) allowed — full zone data exposed" if any(r.get("vulnerable") for r in results) else None,
    }


def _txt_records(domain: str) -> list:
    output = _nslookup("TXT", domain)
    records = []
    for line in output.splitlines():
        m = re.search(r'"([^"]+)"', line)
        if m:
            records.append(m.group(1))
    return records


def check_spf_dmarc_dkim(domain: str) -> dict:
    result = {}

    # SPF
    txt = _txt_records(domain)
    spf_records = [r for r in txt if r.lower().startswith("v=spf1")]
    if spf_records:
        spf = spf_records[0]
        result["spf"] = {
            "present": True,
            "record": spf,
            "all_strict": "-all" in spf,
            "warning": None if "-all" in spf else "SPF does not end with '-all' — soft-fail only, spoofing partially possible",
        }
    else:
        result["spf"] = {
            "present": False,
            "record": None,
            "warning": "No SPF record — email spoofing possible",
        }

    # DMARC
    dmarc_txt = _txt_records(f"_dmarc.{domain}")
    dmarc_records = [r for r in dmarc_txt if r.lower().startswith("v=dmarc1")]
    if dmarc_records:
        dmarc = dmarc_records[0]
        policy_m = re.search(r"p=(\w+)", dmarc)
        policy_val = policy_m.group(1).lower() if policy_m else "none"
        result["dmarc"] = {
            "present": True,
            "record": dmarc,
            "policy": policy_val,
            "warning": None if policy_val in ("quarantine", "reject") else "DMARC policy is 'none' — no enforcement",
        }
    else:
        result["dmarc"] = {
            "present": False,
            "record": None,
            "warning": "No DMARC record — email spoofing possible",
        }

    # DKIM (try common selectors)
    dkim_found = False
    for selector in ("default", "google", "mail", "dkim", "k1", "selector1", "selector2"):
        dkim_txt = _txt_records(f"{selector}._domainkey.{domain}")
        dkim_records = [r for r in dkim_txt if "v=dkim1" in r.lower() or "p=" in r.lower()]
        if dkim_records:
            dkim_found = True
            result["dkim"] = {
                "present": True,
                "selector": selector,
                "record": dkim_records[0][:120],
            }
            break
    if not dkim_found:
        result["dkim"] = {
            "present": False,
            "warning": "No DKIM found (common selectors tried) — email authenticity unverifiable",
        }

    return result


def check_wildcard_dns(domain: str) -> dict:
    rand = "".join(random.choices(string.ascii_lowercase, k=16))
    probe = f"{rand}.{domain}"
    try:
        ip = socket.gethostbyname(probe)
        return {
            "wildcard": True,
            "resolves_to": ip,
            "warning": f"Wildcard DNS configured — {probe} resolves to {ip}",
        }
    except socket.gaierror:
        return {"wildcard": False}
    except Exception as e:
        return {"wildcard": False, "error": str(e)}


def run_dns_audit(domain: str) -> dict:
    """Run all DNS security checks. Returns empty dict for IP targets."""
    if _is_ip(domain):
        return {}
    log.info("DNS audit on %s", domain)
    return {
        "zone_transfer": check_zone_transfer(domain),
        "email_security": check_spf_dmarc_dkim(domain),
        "wildcard": check_wildcard_dns(domain),
    }
