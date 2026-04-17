"""
tool_discovery.py — Dynamically discover all security/recon tools available
on the current Linux machine and format them for the AI engine prompt.
"""

import os
import shutil
from pathlib import Path
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
    "smbclient", "smbmap", "rpcclient", "ldapsearch", "ldapdomaindump",
    "impacket", "responder", "kerbrute", "bloodhound",
    # ── SNMP ──────────────────────────────────────────────────────────────
    "snmpwalk", "onesixtyone",
    # ── Proxies / interceptors ────────────────────────────────────────────
    "mitmproxy", "burpsuite",
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

# Extra names to probe inside /opt — maps display name → possible binary names
_OPT_TOOLS: Dict[str, list] = {
    "burpsuite":       ["BurpSuiteCommunity", "BurpSuitePro", "burpsuite"],
    "burpsuitepro":    ["BurpSuitePro"],
    "metasploit":      ["msfconsole"],
    "enum4linux-ng":   ["enum4linux-ng.py", "enum4linux-ng"],
    "theharvester":    ["theHarvester.py", "theHarvester"],
    "ldapdomaindump":  ["ldapdomaindump"],
    "smbmap":          ["smbmap"],
    "feroxbuster":     ["feroxbuster"],
    "testssl.sh":      ["testssl.sh"],
    "amass":           ["amass"],
    "onesixtyone":     ["onesixtyone"],
    "wfuzz":           ["wfuzz"],
}


def _find_in_opt(binary_names: list) -> str | None:
    """Walk /opt recursively and return the first match for any binary name."""
    opt = Path("/opt")
    if not opt.exists():
        return None
    for binary in binary_names:
        for candidate in opt.rglob(binary):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


def discover_available_tools() -> Dict[str, str]:
    """
    Return a mapping of {tool_name: absolute_path} for every tool
    found either on PATH (shutil.which) or inside /opt/.
    """
    available: Dict[str, str] = {}
    seen: set[str] = set()

    # 1. Standard PATH lookup
    for tool in _KNOWN_TOOLS:
        if tool in seen:
            continue
        seen.add(tool)
        path = shutil.which(tool)
        if path:
            available[tool] = path

    # 2. /opt scan for tools that may not be on PATH
    for display_name, binaries in _OPT_TOOLS.items():
        if display_name in available:
            continue  # already found via PATH
        # also try PATH first for these
        for b in binaries:
            p = shutil.which(b)
            if p:
                available[display_name] = p
                break
        else:
            p = _find_in_opt(binaries)
            if p:
                available[display_name] = p

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
