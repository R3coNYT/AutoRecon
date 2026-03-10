import re
from typing import Any, Dict, List, Optional

PORT_LINE_RE = re.compile(
    r"^(?P<port>\d+)\/(?P<proto>\w+)\s+open\s+(?P<service>[\w\-\./]+)\s*(?P<version>.*)$",
    re.IGNORECASE
)

def parse_nmap_text(nmap_text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ip": None,
        "rdns": None,
        "open_ports": []
    }

    if not nmap_text or nmap_text.startswith("[nmap_error]"):
        out["error"] = nmap_text
        return out

    # IP + rDNS
    # Exemple: "Nmap scan report for flavien-marchand.fr (217.154.8.239)"
    m = re.search(r"Nmap scan report for\s+(.+?)\s+\(([\d\.]+)\)", nmap_text)
    if m:
        out["rdns"] = m.group(1).strip()
        out["ip"] = m.group(2).strip()
    else:
        # fallback IP-only
        m2 = re.search(r"Nmap scan report for\s+([\d\.]+)", nmap_text)
        if m2:
            out["ip"] = m2.group(1).strip()

    # Parse lignes ports
    lines = nmap_text.splitlines()
    in_ports = False
    for line in lines:
        if line.strip().startswith("PORT"):
            in_ports = True
            continue
        if in_ports:
            # fin de table (vide ou "Service detection performed...")
            if not line.strip() or line.strip().lower().startswith("service detection performed"):
                in_ports = False
                continue

            lm = PORT_LINE_RE.match(line.strip())
            if not lm:
                continue

            port = int(lm.group("port"))
            proto = lm.group("proto").lower()
            service = lm.group("service").strip()
            version_raw = (lm.group("version") or "").strip()

            # tentative de split produit/version (best effort)
            product = None
            version = None
            extrainfo = None

            # ex: "OpenSSH 10.0p2 (protocol 2.0)"
            if version_raw:
                product = version_raw
                # petit parse "Product X.Y"
                pm = re.match(r"^([A-Za-z0-9\-\._]+)\s+([0-9][^\s]*)\s*(.*)$", version_raw)
                if pm:
                    product = pm.group(1)
                    version = pm.group(2)
                    extrainfo = pm.group(3).strip() if pm.group(3) else None

            out["open_ports"].append({
                "port": port,
                "proto": proto,
                "service": service,
                "version_raw": version_raw,
                "product": product,
                "version": version,
                "extrainfo": extrainfo
            })

    return out
