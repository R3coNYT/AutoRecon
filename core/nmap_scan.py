import subprocess
import shutil
import sys
from pathlib import Path

NMAP_BIN = shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"

# On Windows, SYN scan (-sS, the default) requires raw socket access (admin).
# Use TCP connect scan (-sT) instead, which works without elevated privileges.
_WINDOWS = sys.platform == "win32"


def nmap_service_scan(host: str, output_dir: Path, full_scan=False, ports=None):

    safe_host = host.replace("/", "_").replace(":", "_")
    xml_path = ""
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        xml_path = output_dir / f"nmap_{safe_host}.xml"

    cmd = [NMAP_BIN, "-sV", "-T4"]

    # On Windows use TCP connect scan to avoid raw-socket privilege errors
    if _WINDOWS:
        cmd += ["-sT"]

    # scan complet
    if full_scan and not ports:
        cmd += ["-sC", "-p-"]

    # ports venant de masscan
    if ports:
        cmd += ["-p", ports]

    # scan classique si rien trouvé par masscan
    if not full_scan and not ports:
        cmd += ["--top-ports", "200"]

    cmd += ["-oX", xml_path, host]

    try:
        result = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            timeout=600 if full_scan else 180
        )
        txt_output = result.decode("utf-8", "ignore")

    except subprocess.CalledProcessError as e:
        output = e.output.decode("utf-8", "ignore") if e.output else ""
        if "requires root" in output.lower() or "you requested a scan type" in output.lower():
            txt_output = f"[nmap_error] Nmap requires administrator privileges for this scan type. Run as admin or use TCP connect scan (-sT).\n{output}"
        else:
            txt_output = f"[nmap_error] {e}\n{output}"
    except subprocess.TimeoutExpired:
        txt_output = "[nmap_error] Nmap scan timed out."
    except Exception as e:
        txt_output = f"[nmap_error] {e}"

    return txt_output, xml_path

def infer_scheme_from_nmap(nmap_text: str) -> str:
    if "443/tcp open" in nmap_text:
        return "https"
    if "80/tcp open" in nmap_text:
        return "http"
    return "https"