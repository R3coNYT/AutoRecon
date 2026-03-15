import re
import subprocess
import ipaddress
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

_IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
_GREPABLE_UP_RE = re.compile(r'^Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\s+.*Status:\s+Up\b', re.IGNORECASE)
NMAP_BIN = shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"


def _parse_nmap_hosts(output):
    """Extract alive IP addresses from nmap output."""
    alive = []
    for line in output.splitlines():
        m_grep = _GREPABLE_UP_RE.search(line)
        if m_grep:
            alive.append(m_grep.group(1))
            continue

        if "Nmap scan report for" not in line:
            continue
        # Formats:
        #   "Nmap scan report for 192.168.1.1"           (no DNS, -n)
        #   "Nmap scan report for hostname (192.168.1.1)" (with DNS)
        m = _IP_RE.findall(line)
        if m:
            alive.append(m[-1])  # last IP on the line is always the address
    return alive


def _run_nmap_sn(target, extra_args=None):
    """Run nmap -sn with the given extra_args and return a list of alive IPs."""
    cmd = [NMAP_BIN, "-sn", "-n", "-oG", "-"]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(target)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    return _parse_nmap_hosts(output)


def nmap_discover(target):
    try:
        # --- Pass 1: full probe set (requires admin/root for raw-socket probes)
        # -PR  : ARP ping  — most reliable on local LAN, no privileges needed
        # -PE/PP/PM: ICMP probes (need admin; silently skipped if not available)
        # -PS/PA: TCP SYN/ACK probes on common ports
        alive = _run_nmap_sn(
            target,
            extra_args=[
                "-PR",
                "-PE", "-PP", "-PM",
                "-PS22,80,443,8000,8080,8443,9443,3389,5900,51821",
                "-PA80,443",
            ]
        )

        # --- Pass 2: fallback without raw-socket privileges (TCP connect)
        # Runs only when pass-1 found nothing, to handle non-admin contexts.
        if not alive:
            alive = _run_nmap_sn(
                target,
                extra_args=[
                    "--unprivileged",
                    "-PS22,80,443,8000,8080,8443,9443,3389,5900,51821",
                ]
            )

        return alive

    except Exception:
        return []


def discover_hosts(ips, threads=10):
    targets = []
    
    for ip in ips:

        if "/" in ip:
            targets.append(ip)

        else:
            try:
                ipaddress.ip_address(ip)
                targets.append(ip)
            except:
                continue

    alive = []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(nmap_discover, target): target for target in targets}
        
        for fut in as_completed(futures):

            try:
                res = fut.result()
                alive.extend(res)

            except:
                pass

    alive = list(set(alive))

    def ip_sort(ip):
        return tuple(map(int, ip.split(".")))

    return sorted(alive, key=ip_sort)