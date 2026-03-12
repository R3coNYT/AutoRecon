import subprocess, os

from rich import json

def nmap_service_scan(host: str, output_dir: str, full_scan=False, ports=None):

    safe_host = host.replace("/", "_").replace(":", "_")
    xml_path = ""
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        xml_path = os.path.join(output_dir, f"nmap_{safe_host}.xml")

    cmd = ["nmap", "-sV", "-T4"]

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
            timeout=800 if full_scan else 180
        )

        txt_output = result.decode("utf-8", "ignore")

    except Exception as e:
        txt_output = f"[nmap_error] {e}"

    return txt_output, xml_path

def infer_scheme_from_nmap(nmap_text: str) -> str:
    if "443/tcp open" in nmap_text:
        return "https"
    if "80/tcp open" in nmap_text:
        return "http"
    return "https"