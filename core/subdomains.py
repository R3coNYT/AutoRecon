import sys
import subprocess
import shutil
import logging
import re
import requests
from typing import List
from pathlib import Path

log = logging.getLogger("recon-audit")


def _write_fallback(out_file: Path, target: str):
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(target.strip() + "\n")


def _run_sublist3r(target: str, out_file: Path) -> List[str]:
    project_root = Path(__file__).resolve().parent.parent
    sublist3r_py = project_root / "Sublist3r" / "sublist3r.py"
    if not sublist3r_py.exists():
        log.warning("Sublist3r not found at %s", sublist3r_py)
        return []
    cmd = [sys.executable, str(sublist3r_py), "-d", target, "-o", str(out_file)]
    subprocess.run(cmd, cwd=str(project_root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if not out_file.exists():
        return []
    with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def _run_subfinder(target: str) -> List[str]:
    subfinder = shutil.which("subfinder")
    if not subfinder:
        return []
    try:
        proc = subprocess.run(
            [subfinder, "-d", target, "-silent"],
            capture_output=True, text=True, timeout=120,
        )
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    except Exception as e:
        log.debug("subfinder error: %s", e)
        return []


def _run_crtsh(target: str) -> List[str]:
    """Query crt.sh Certificate Transparency logs for subdomains."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{target}&output=json",
            timeout=20,
            headers={"User-Agent": "ReconAudit/1.0"},
        )
        if r.status_code != 200:
            return []
        subs = set()
        for entry in r.json():
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if line.endswith(f".{target}") or line == target:
                    subs.add(line.lower())
        return list(subs)
    except Exception as e:
        log.debug("crt.sh error: %s", e)
        return []


def _dns_bruteforce(target: str, out_dir: Path) -> List[str]:
    """Brute-force subdomains using the local wordlist."""
    from pathlib import Path as _Path
    wordlist = _Path(__file__).resolve().parents[1] / "wordlists" / "File_Dir.txt"
    if not wordlist.exists():
        return []
    subs = []
    try:
        import socket
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and "/" not in line]
        # Limit to reasonable count for DNS brute-force
        for word in words[:500]:
            probe = f"{word}.{target}"
            try:
                socket.gethostbyname(probe)
                subs.append(probe)
            except socket.gaierror:
                pass
    except Exception as e:
        log.debug("DNS bruteforce error: %s", e)
    return subs


def run_sublist3r(target: str, out_dir: Path) -> List[str]:
    """Multi-source subdomain enumeration: Sublist3r + subfinder + crt.sh + DNS brute-force."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "subdomains.txt"

    all_subs: set = set()
    all_subs.add(target)

    # 1) Sublist3r
    log.info("Subdomain enumeration: Sublist3r on %s", target)
    subs_sublist3r = _run_sublist3r(target, out_file)
    if subs_sublist3r:
        log.info("Sublist3r found %d subdomains", len(subs_sublist3r))
        all_subs.update(subs_sublist3r)
    else:
        _write_fallback(out_file, target)

    # 2) subfinder (projectdiscovery)
    log.info("Subdomain enumeration: subfinder on %s", target)
    subs_subfinder = _run_subfinder(target)
    if subs_subfinder:
        log.info("subfinder found %d subdomains", len(subs_subfinder))
        all_subs.update(subs_subfinder)

    # 3) Certificate Transparency (crt.sh)
    log.info("Subdomain enumeration: crt.sh on %s", target)
    subs_crtsh = _run_crtsh(target)
    if subs_crtsh:
        log.info("crt.sh found %d subdomains", len(subs_crtsh))
        all_subs.update(subs_crtsh)

    # 4) DNS brute-force (wordlist)
    log.info("Subdomain enumeration: DNS brute-force on %s", target)
    subs_brute = _dns_bruteforce(target, out_dir)
    if subs_brute:
        log.info("DNS brute-force found %d subdomains", len(subs_brute))
        all_subs.update(subs_brute)

    result = sorted(all_subs)
    # Persist combined list
    with open(out_dir / "subdomains_all.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(result))

    log.info("Total unique subdomains after all sources: %d", len(result))
    return result