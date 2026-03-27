"""
Extended subdomain OSINT via theHarvester.
Discovers emails, additional subdomains, and employee names from public sources.
Falls back gracefully if theHarvester is not installed.
"""
import json
import logging
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

log = logging.getLogger("recon-audit")

_SOURCES = "bing,crtsh,dnsdumpster,duckduckgo,hackertarget,rapiddns,urlscan"


def _harvester_available() -> bool:
    return shutil.which("theHarvester") is not None or shutil.which("theharvester") is not None


def _cmd() -> str:
    return "theHarvester" if shutil.which("theHarvester") else "theharvester"


def run_theharvester(domain: str, output_dir: Path | None = None,
                     timeout: int = 120) -> dict:
    """
    Run theHarvester against *domain*.

    Returns:
    {
      "emails": ["user@example.com", ...],
      "subdomains": ["mail.example.com", ...],
      "ips": ["1.2.3.4", ...],
      "hosts": ["mail.example.com:1.2.3.4", ...],
      "error": None or str,
    }
    """
    empty = {"emails": [], "subdomains": [], "ips": [], "hosts": [], "error": None}

    if not _harvester_available():
        log.debug("theHarvester not found — skipping OSINT")
        empty["error"] = "theHarvester not installed"
        return empty

    with tempfile.TemporaryDirectory() as tmp:
        out_xml = Path(tmp) / "harvest"  # theHarvester appends .xml automatically

        cmd = [
            _cmd(),
            "-d", domain,
            "-b", _SOURCES,
            "-f", str(out_xml),
            "-l", "200",
        ]

        try:
            proc = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True,
            )
        except subprocess.TimeoutExpired:
            log.warning("theHarvester timed out for %s", domain)
            empty["error"] = "timeout"
            return empty
        except Exception as e:
            log.warning("theHarvester error: %s", e)
            empty["error"] = str(e)
            return empty

        # Try JSON output first (newer theHarvester versions)
        json_file = Path(str(out_xml) + ".json")
        xml_file = Path(str(out_xml) + ".xml")

        if json_file.exists():
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                result = {
                    "emails": list(set(data.get("emails", []) or [])),
                    "subdomains": list(set(data.get("hosts", []) or [])),
                    "ips": list(set(data.get("ips", []) or [])),
                    "hosts": list(set(data.get("hosts", []) or [])),
                    "error": None,
                }
                _log_summary(domain, result)
                return result
            except Exception as e:
                log.debug("JSON parse failed for theHarvester output: %s", e)

        # Fallback: parse XML
        if xml_file.exists():
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                emails = [e.text.strip() for e in root.findall(".//email") if e.text]
                hosts = [h.text.strip() for h in root.findall(".//host") if h.text]
                ips = [i.text.strip() for i in root.findall(".//ip") if i.text]
                result = {
                    "emails": list(set(emails)),
                    "subdomains": list(set(hosts)),
                    "ips": list(set(ips)),
                    "hosts": list(set(hosts)),
                    "error": None,
                }
                _log_summary(domain, result)
                return result
            except Exception as e:
                log.warning("theHarvester XML parse error: %s", e)

        # Last resort: parse stdout with regex
        stdout = proc.stdout or ""
        emails = list(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", stdout)))
        hosts = list(set(re.findall(r"[a-zA-Z0-9\-\.]+\." + re.escape(domain), stdout, re.IGNORECASE)))
        ips = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", stdout)))
        result = {
            "emails": emails,
            "subdomains": hosts,
            "ips": ips,
            "hosts": hosts,
            "error": None,
        }
        _log_summary(domain, result)
        return result


def _log_summary(domain: str, result: dict):
    log.info("theHarvester results for %s — %d emails, %d subdomains, %d IPs",
             domain,
             len(result.get("emails", [])),
             len(result.get("subdomains", [])),
             len(result.get("ips", [])))
