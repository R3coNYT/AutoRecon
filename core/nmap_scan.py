import subprocess

def nmap_service_scan(host: str, full_scan=False) -> str:

    if full_scan:
        cmd = ["nmap", "-sV", "-sC", "-T4", "-p-", host]
    else:
        cmd = ["nmap", "-sV", "-T4", "--top-ports", "200", host]

    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            timeout=800 if full_scan else 180
        ).decode("utf-8", "ignore")
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

def nmap_scan_ports(target, ports):
    port_str = ",".join(map(str, ports))

    cmd = [
        "nmap",
        "-sV",
        "-sC",
        "-Pn",
        "-p", port_str,
        target
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    return result.stdout

