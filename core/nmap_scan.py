import subprocess, os

def nmap_service_scan(host: str, output_dir: str, full_scan=False) -> str:

    safe_host = host.replace("/", "_").replace(":", "_")

    xml_path = os.path.join(output_dir, f"nmap_{safe_host}.xml")

    if full_scan:
        cmd = ["nmap", "-sV", "-sC", "-T4", "-p-", "-oX", xml_path, host]
    else:
        cmd = ["nmap", "-sV", "-T4", "--top-ports", "200", "-oX", xml_path, host]

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