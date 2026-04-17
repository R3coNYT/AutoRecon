import subprocess
import shutil
import sys
from pathlib import Path

NMAP_BIN = shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"

# On Windows, SYN scan (-sS, the default) requires raw socket access (admin).
# Use TCP connect scan (-sT) instead, which works without elevated privileges.
_WINDOWS = sys.platform == "win32"


def _build_nmap_cmd(host: str, xml_path, full_scan: bool, ports, skip_discovery: bool) -> list:
    cmd = [NMAP_BIN, "-sV", "-T4"]

    if skip_discovery:
        cmd += ["-Pn"]

    # On Windows use TCP connect scan to avoid raw-socket privilege errors
    if _WINDOWS:
        cmd += ["-sT"]

    if full_scan and not ports:
        cmd += ["-sC", "-p-"]

    if ports:
        cmd += ["-p", ports]

    if not full_scan and not ports:
        cmd += ["--top-ports", "200"]

    cmd += ["-oX", str(xml_path), host]
    return cmd


def _run_nmap_cmd(cmd: list, full_scan: bool, timeout, timeout_full) -> str:
    try:
        if full_scan:
            _timeout = timeout_full if timeout_full is not None else (timeout if timeout is not None else 1200)
        else:
            _timeout = timeout if timeout is not None else 300
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=_timeout)
        return result.decode("utf-8", "ignore")
    except subprocess.CalledProcessError as e:
        output = e.output.decode("utf-8", "ignore") if e.output else ""
        if "requires root" in output.lower() or "you requested a scan type" in output.lower():
            return (
                f"[nmap_error] Nmap requires administrator privileges for this scan type. "
                f"Run as admin or use TCP connect scan (-sT).\n{output}"
            )
        return f"[nmap_error] {e}\n{output}"
    except subprocess.TimeoutExpired:
        return "[nmap_error] Nmap scan timed out."
    except Exception as e:
        return f"[nmap_error] {e}"


def _hosts_up(nmap_text: str) -> bool:
    """Return True if nmap reported at least one host up."""
    import re
    # e.g. "Nmap done: 1 IP address (1 host up)"  or  "(0 hosts up)"
    match = re.search(r"\((\d+) hosts? up\)", nmap_text)
    if match:
        return int(match.group(1)) > 0
    # If no summary line (error / empty output) assume something went wrong
    return False


def nmap_service_scan(host: str, output_dir: Path, full_scan=False, ports=None, timeout=None, timeout_full=None):

    safe_host = host.replace("/", "_").replace(":", "_")
    xml_path = ""
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        xml_path = output_dir / f"nmap_{safe_host}.xml"

    # ── First pass: without -Pn ───────────────────────────────────────────
    cmd = _build_nmap_cmd(host, xml_path, full_scan, ports, skip_discovery=False)
    txt_output = _run_nmap_cmd(cmd, full_scan, timeout, timeout_full)

    # ── Retry with -Pn if 0 hosts up ─────────────────────────────────────
    if not _hosts_up(txt_output) and "[nmap_error]" not in txt_output:
        cmd_pn = _build_nmap_cmd(host, xml_path, full_scan, ports, skip_discovery=True)
        txt_output = _run_nmap_cmd(cmd_pn, full_scan, timeout, timeout_full)

    return txt_output, xml_path

def infer_scheme_from_nmap(nmap_text: str) -> str:
    if "443/tcp open" in nmap_text:
        return "https"
    if "80/tcp open" in nmap_text:
        return "http"
    return "https"