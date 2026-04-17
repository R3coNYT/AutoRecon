"""
tool_discovery.py — Dynamically discover all security/recon tools available
on the current Linux machine and format them for the AI engine prompt.
"""

import shutil
from typing import Dict

# Comprehensive catalogue of recon/pentest tools to probe
_KNOWN_TOOLS: list[str] = [
    # ── Network scanning ──────────────────────────────────────────────────
    "nmap", "masscan", "zmap", "rustscan", "unicornscan",
    # ── Web probing / fuzzing ─────────────────────────────────────────────
    "httpx", "ffuf", "gobuster", "dirb", "feroxbuster", "wfuzz",
    "nikto", "whatweb", "wafw00f", "katana",
    # ── Subdomain / DNS ───────────────────────────────────────────────────
    "sublist3r", "amass", "subfinder", "assetfinder", "dnsx",
    "massdns", "dnsrecon", "fierce", "dnsenum",
    # ── OSINT ─────────────────────────────────────────────────────────────
    "theharvester", "recon-ng", "sherlock", "holehe",
    # ── Vulnerability scanning ────────────────────────────────────────────
    "nuclei", "openvas", "nessus",
    # ── Web-application attacks ───────────────────────────────────────────
    "sqlmap", "commix", "xsstrike", "dalfox",
    # ── CMS scanners ──────────────────────────────────────────────────────
    "wpscan", "joomscan", "droopescan",
    # ── Password / brute-force ────────────────────────────────────────────
    "hydra", "medusa", "ncrack", "patator",
    "john", "hashcat", "crunch",
    # ── TLS / SSL ─────────────────────────────────────────────────────────
    "testssl.sh", "testssl", "sslscan", "sslyze",
    # ── Screenshots ───────────────────────────────────────────────────────
    "gowitness", "aquatone", "eyewitness",
    # ── Parameter discovery ───────────────────────────────────────────────
    "arjun", "x8",
    # ── Exploit frameworks ────────────────────────────────────────────────
    "msfconsole", "msfvenom", "searchsploit",
    # ── Windows / SMB / AD ───────────────────────────────────────────────
    "crackmapexec", "cme", "enum4linux", "enum4linux-ng",
    "smbclient", "rpcclient", "ldapsearch", "impacket",
    "responder", "kerbrute", "bloodhound",
    # ── SNMP ──────────────────────────────────────────────────────────────
    "snmpwalk", "onesixtyone",
    # ── Proxies / interceptors ────────────────────────────────────────────
    "mitmproxy",
    # ── Cloud ─────────────────────────────────────────────────────────────
    "aws", "gcloud", "az", "terraform",
    # ── Container / infra ────────────────────────────────────────────────
    "docker", "kubectl", "helm",
    # ── Network utilities ─────────────────────────────────────────────────
    "nc", "ncat", "socat", "tcpdump", "tshark", "wireshark",
    "curl", "wget",
    # ── Reverse engineering ───────────────────────────────────────────────
    "gdb", "radare2", "r2", "strace", "ltrace", "strings",
    # ── Misc / scripting ─────────────────────────────────────────────────
    "python3", "python", "ruby", "perl", "go",
    "jq", "xmllint", "openssl", "git",
]


def discover_available_tools() -> Dict[str, str]:
    """
    Return a mapping of {tool_name: absolute_path} for every tool
    from _KNOWN_TOOLS that is found on PATH via shutil.which().
    """
    available: Dict[str, str] = {}
    seen: set[str] = set()
    for tool in _KNOWN_TOOLS:
        if tool in seen:
            continue
        seen.add(tool)
        path = shutil.which(tool)
        if path:
            available[tool] = path
    return available


def format_tools_for_prompt(available: Dict[str, str]) -> str:
    """
    Render the discovered tools as a human-readable block suitable
    for embedding in the AI system/user prompt.
    """
    if not available:
        return "No tools detected on PATH."
    lines = [f"  - {name}  ({path})" for name, path in sorted(available.items())]
    return "\n".join(lines)
