import json
from pathlib import Path
from rich.console import Console

console = Console()


def generate_html_map(
    assets:       list,
    output_dir:   Path,
    plugin_base:  Path,
    exposure:     dict,
    criticality:  dict,
    attack_paths: list,
) -> None:
    """
    Generate the interactive Vis-Network topology HTML file.
    All analytics (exposure, criticality, attack_paths) are pre-computed by the caller.
    """
    output_dir  = Path(output_dir)
    plugin_base = Path(plugin_base)
    html_file   = output_dir / "topology.html"

    static_dir = plugin_base / "static"
    static_dir.mkdir(exist_ok=True)

    nodes: list = []
    edges: list = []
    edge_ids    = 0
    db_ports    = [3306, 5432]

    # â”€â”€ Nodes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    for asset in assets:
        color = (
            "#ff4c4c" if asset["risk_score"] >= 7
            else "#ffae42" if asset["risk_score"] >= 4
            else "#4caf50"
        )
        nodes.append({
            "id":       asset["ip"],
            "label":    asset["ip"],
            "group":    asset["zone"],
            "color":    color,
            "type":     asset["classification"],
            "risk":     asset["risk_score"],
            "services": [s.get("port") for s in asset.get("services", [])],
            "title": (
                f"IP: {asset['ip']}\n"
                f"Zone: {asset['zone']}\n"
                f"Type: {asset['classification']}\n"
                f"Risk Score: {asset['risk_score']}\n"
                f"Services: {', '.join(str(s.get('port')) for s in asset.get('services', []))}"
            ),
        })

    # â”€â”€ Edges: AD + DB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    for a in assets:
        for b in assets:
            if a["ip"] == b["ip"]:
                continue

            if a["classification"] == "Domain Controller" and b["classification"] == "Windows Server":
                edge_ids += 1
                edges.append({
                    "id": f"e{edge_ids}", "from": a["ip"], "to": b["ip"],
                    "label": "AD", "dashes": True, "color": {"color": "#888"},
                })

            if a["classification"] == "Web Server":
                is_db_host = any(
                    int(svc["port"]) in db_ports
                    for svc in b.get("services", [])
                    if str(svc.get("port", "")).isdigit()
                )
                if is_db_host:
                    edge_ids += 1
                    edges.append({
                        "id": f"e{edge_ids}", "from": a["ip"], "to": b["ip"],
                        "label": "DB", "color": {"color": "#00bcd4"},
                    })

    # â”€â”€ Traceroute nodes/edges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    known_node_ids = {n["id"] for n in nodes}

    def add_hop_node(ip_):
        if ip_ in known_node_ids:
            return
        known_node_ids.add(ip_)
        nodes.append({
            "id": ip_, "label": ip_, "group": "PATH", "color": "#b0bec5",
            "type": "Router / Hop", "risk": 0, "services": [],
            "title": f"Traceroute hop: {ip_}",
        })

    for a in assets:
        path = a.get("trace_path")
        if not path or len(path) < 2:
            continue
        for hop_ip in path[:-1]:
            add_hop_node(hop_ip)
        for i in range(len(path) - 1):
            edge_ids += 1
            edges.append({
                "id": f"e{edge_ids}", "from": path[i], "to": path[i + 1],
                "label": "TR", "dashes": True, "color": {"color": "#9aa0a6"},
                "traceroute": True, "hidden": True,
            })

    trace_paths = {
        a["ip"]: a.get("trace_path")
        for a in assets if a.get("trace_path")
    }

    # â”€â”€ Protocol-level edges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def has_port(asset, port):
        return any(
            int(s.get("port", -1)) == port
            for s in asset.get("services", [])
            if str(s.get("port", "")).isdigit()
        )

    def add_edge(frm, to, label, color="#666", dashes=False):
        nonlocal edge_ids
        edge_ids += 1
        edges.append({
            "id": f"e{edge_ids}", "from": frm, "to": to,
            "label": label, "dashes": dashes, "color": {"color": color},
            "hidden": False,
        })

    dns_servers = [a for a in assets if has_port(a, 53)]
    web_servers = [a for a in assets if has_port(a, 80) or has_port(a, 443)]
    smb_servers = [a for a in assets if has_port(a, 445)]
    ssh_servers = [a for a in assets if has_port(a, 22)]
    rdp_servers = [a for a in assets if has_port(a, 3389)]
    clients     = [a for a in assets if a["classification"] in ("Workstation / Unknown", "Windows")]

    for c in clients:
        for d in dns_servers:
            add_edge(c["ip"], d["ip"], "DNS", color="#9c27b0", dashes=True)
        for w in web_servers:
            add_edge(c["ip"], w["ip"], "HTTP", color="#00bcd4", dashes=True)
        for s in smb_servers:
            add_edge(c["ip"], s["ip"], "SMB", color="#ffc107", dashes=True)

    for a in assets:
        for t in ssh_servers:
            if a["ip"] != t["ip"]:
                edge_ids += 1
                edges.append({
                    "id": f"e{edge_ids}", "from": a["ip"], "to": t["ip"],
                    "label": "SSH", "dashes": True, "color": {"color": "#4caf50"},
                    "admin": True, "hidden": True,
                })
        for t in rdp_servers:
            if a["ip"] != t["ip"]:
                edge_ids += 1
                edges.append({
                    "id": f"e{edge_ids}", "from": a["ip"], "to": t["ip"],
                    "label": "RDP", "dashes": True, "color": {"color": "#ff9800"},
                    "admin": True, "hidden": True,
                })


    # -- Load HTML template from file and substitute placeholders
    template_file = plugin_base / "templates" / "topology_template.html"
    html_content = template_file.read_text("utf-8")
    html_content = (
        html_content
        .replace("%NODES%",        json.dumps(nodes))
        .replace("%EDGES%",        json.dumps(edges))
        .replace("%EXPOSURE%",     json.dumps(exposure))
        .replace("%CRITICALITY%",  json.dumps(criticality))
        .replace("%ATTACK_PATHS%", json.dumps(attack_paths))
        .replace("%TRACE_PATHS%",  json.dumps(trace_paths))
        .replace("%CRIT_CRITICAL%", str(criticality.get("critical", 0)))
        .replace("%CRIT_HIGH%",    str(criticality.get("high", 0)))
        .replace("%CRIT_MEDIUM%",  str(criticality.get("medium", 0)))
        .replace("%CRIT_LOW%",     str(criticality.get("low", 0)))
    )


    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    console.print(f"[green][+] Interactive topology map: {html_file}[/green]")
