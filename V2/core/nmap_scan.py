import subprocess
from core.utils import is_ip

def nmap_service_scan(host: str) -> str:
    cmd = ["nmap", "-sV", "-T4", "--top-ports", "200", host]
    
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=180).decode("utf-8", "ignore")
    except Exception as e:
        out = f"[nmap_error] {e}"
    return out

def infer_scheme_from_nmap(nmap_text: str) -> str:
    if "443/tcp open" in nmap_text:
        return "https"
    if "80/tcp open" in nmap_text:
        return "http"
    # default safe
    return "https"
