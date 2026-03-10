import subprocess
import xml.etree.ElementTree as ET
import json
import csv
import os
import re
import platform
import questionary
import shutil
from pathlib import Path
from ipaddress import ip_address, ip_network
from pypdf import PdfReader, PdfWriter
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, cm
from reportlab.lib import pagesizes
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import A4
from io import BytesIO
from rich.console import Console
from core.banner import print_banner
from core.report_pdf import _load_personalization
from core.client_folder_select import select_or_create_client_folder

console = Console()

# ======================================================
# HEADER
# ======================================================
def draw_header(title="Results Browser"):
    console.clear()
    print_banner()
    console.rule("[bold red]AutoRecon Console[/bold red]")
    console.print(f"[bold red]{title}[/bold red]")

def safe_ask(q):
    result = q.ask()
    if result is None:
        raise KeyboardInterrupt
    return result

class Plugin:
    name = "Mapping"
    description = "Advanced Information System Mapping & Risk Classification"

    def __init__(self):
        self.private_ranges = [
            ip_network("10.0.0.0/8"),
            ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16")
        ]

        self.plugin_base = Path(__file__).parent
        self.results_base = self.plugin_base / "results"
        self.results_base.mkdir(exist_ok=True)
        self.default_gw = None
        if platform.system() != "Windows":
            self.default_gw = self._detect_default_gateway()

    # ======================================================
    # FILE OPEN (cross-platform)
    # ======================================================
    def open_file(self, path):
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.run(["open", path])
        else:
            if shutil.which("chromium"):
                subprocess.Popen(
                    ["chromium", "--new-tab", str(path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
            else:
                subprocess.Popen(
                    ["firefox", "--new-tab", str(path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )

    # ======================================================
    # HOST DISCOVERY (Ping Sweep)
    # ======================================================
    def discover_alive_hosts(self, target):
        console.print("[*] Discovering alive hosts...")

        try:
            result = subprocess.run(
                [
                    "nmap",
                    "-sn",
                    "-n",
                    "-PE",
                    "-PP",
                    "-PM",
                    "-PS80,443",
                    "-PA80,443",
                    target
                ],
                capture_output=True,
                text=True
            )

            alive = []

            for line in result.stdout.splitlines():
                if "Nmap scan report for" in line:
                    ip = line.split()[-1]
                    alive.append(ip)

            console.print(f"[green][+] {len(alive)} hosts alive[/green]")

            return alive

        except Exception as e:
            console.print(f"[red]Host discovery failed: {e}[/red]")
            return []

    # ======================================================
    # RUN NMAP
    # ======================================================
    def run_nmap_scan(self, target, output_xml):
        alive_hosts = self.discover_alive_hosts(target)

        if not alive_hosts:
            console.print("[red]No alive hosts found.[/red]")
            return

        console.print("[*] Running Nmap scan on alive hosts...")

        subprocess.run([
            "nmap",
            "-sS",
            "-sV",
            "-O",
            "--traceroute",
            "-T4",
            "-oX", str(output_xml),
            *alive_hosts
        ])
    
    # ======================================================
    # DEFAULT GATEWAY DETECTION
    # ======================================================
    def _detect_default_gateway(self):
        try:
            out = subprocess.check_output(["ip", "route", "show", "default"], text=True).strip()
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except:
            pass
        return None

    # ======================================================
    # CLASSIFICATION
    # ======================================================
    def classify_host(self, services, ip=None):
        ports = [int(s["port"]) for s in services]

        if self.default_gw and ip == self.default_gw:
            return "Router / Gateway"
        if any(p in ports for p in [389, 636, 88]):
            return "Domain Controller"
        if 22 in ports:
            return "Linux Server"
        if 80 in ports or 443 in ports:
            return "Web Server"
        if 3389 in ports:
            return "Windows Server"
        if 5357 in ports:
            return "Windows"
        if 9100 in ports or 515 in ports:
            return "Printer / Printing Server"
        
        return "Workstation / Unknown"

    def detect_zone(self, ip):
        ip_obj = ip_address(ip)
        for network in self.private_ranges:
            if ip_obj in network:
                return "LAN"
        return "DMZ / External"

    def compute_risk_score(self, services, zone, classification):
        score = 0
        risky_ports = [22, 3389, 445, 21, 25]

        for s in services:
            if int(s["port"]) in risky_ports:
                score += 2

        if zone == "DMZ / External":
            score += 3
        if classification == "Domain Controller":
            score += 5

        return min(score, 10)

    # ======================================================
    # PARSE NMAP
    # ======================================================
    def parse_nmap(self, xml_file):
        tree = ET.parse(xml_file)
        root = tree.getroot()
        assets = []

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            ip = host.find("address").get("addr")

            services = []
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    services.append({
                        "port": port.get("portid")
                    })

            classification = self.classify_host(services, ip=ip)
            zone = self.detect_zone(ip)
            risk_score = self.compute_risk_score(services, zone, classification)

            assets.append({
                "ip": ip,
                "zone": zone,
                "classification": classification,
                "risk_score": risk_score,
                "services": services
            })

        return assets
    
    # ======================================================
    # PARSE TRACEROUTES
    # ======================================================
    def parse_traceroutes(self, xml_file):
        tree = ET.parse(xml_file)
        root = tree.getroot()

        traces = {}

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            addr = host.find("address")
            if addr is None:
                continue
            dest_ip = addr.get("addr")

            trace = host.find("trace")
            if trace is None:
                continue

            hops = []
            hop_ips = []

            for hop in trace.findall("hop"):
                hop_ip = hop.get("ipaddr")
                ttl = hop.get("ttl")
                rtt = hop.get("rtt")

                if not hop_ip:
                    continue

                try:
                    ttl_i = int(ttl) if ttl else None
                except:
                    ttl_i = None

                try:
                    rtt_f = float(rtt) if rtt else None
                except:
                    rtt_f = None

                hops.append({"ttl": ttl_i, "ip": hop_ip, "rtt": rtt_f})
                hop_ips.append(hop_ip)

            if hops:
                # path = hops + destination
                path = hop_ips[:] + [dest_ip]
                traces[dest_ip] = {"hops": hops, "hop_ips": hop_ips, "path": path}
        return traces

    # ======================================================
    # EXPOSURE SURFACE (by zone)
    # ======================================================
    def compute_exposure_by_zone(self, assets):
        """
        Surface d'exposition = somme pondérée des ports "sensibles" exposés
        + nombre de services ouverts
        (heuristique, mais très utile en stage)
        """
        risky_ports = {22, 3389, 445, 21, 25, 1433, 1521, 3306, 5432, 27017, 6379, 9200}
        exposure = {}

        for a in assets:
            zone = a["zone"]
            exposure.setdefault(zone, {
                "hosts": 0,
                "open_services_total": 0,
                "risky_ports_total": 0,
                "exposure_score": 0
            })

            exposure[zone]["hosts"] += 1
            svcs = a.get("services", [])
            exposure[zone]["open_services_total"] += len(svcs)

            rp = 0
            for s in svcs:
                try:
                    p = int(s["port"])
                    if p in risky_ports:
                        rp += 1
                except Exception:
                    pass

            exposure[zone]["risky_ports_total"] += rp

            # score simple : services ouverts + 3*risky_ports + bonus si DMZ
            score = len(svcs) + (3 * rp)
            if zone != "LAN":
                score += 5
            exposure[zone]["exposure_score"] += score

        # normalisation légère
        for z in exposure:
            h = max(exposure[z]["hosts"], 1)
            exposure[z]["exposure_score_avg"] = round(exposure[z]["exposure_score"] / h, 2)

        return exposure


    # ======================================================
    # CRITICITY MATRIX (Impact x Exposure)
    # ======================================================
    def compute_criticality_matrix(self, assets, exposure_by_zone):
        """
        Impact: basé sur classification (DC > DB > Servers > Workstation)
        Exposure: basé sur score hôte + score zone
        Output: Criticality level + matrix counters
        """
        # impact (1..5)
        impact_map = {
            "Domain Controller": 5,
            "Database Server": 4,
            "Web Server": 3,
            "Windows Server": 3,
            "Linux Server": 3,
            "Workstation / Unknown": 2,
        }

        # buckets
        matrix = {
            "low": 0, "medium": 0, "high": 0, "critical": 0,
            "items": []
        }

        for a in assets:
            impact = impact_map.get(a["classification"], 2)

            zone = a["zone"]
            zone_exposure_avg = exposure_by_zone.get(zone, {}).get("exposure_score_avg", 0)

            # exposure (1..5) : combine risk_score (0..10) + zone exposure avg
            # (heuristique stable)
            raw = (a["risk_score"] * 0.7) + (zone_exposure_avg * 0.3)
            if raw < 2.5:
                exposure_level = 1
            elif raw < 4.5:
                exposure_level = 2
            elif raw < 6.5:
                exposure_level = 3
            elif raw < 8.0:
                exposure_level = 4
            else:
                exposure_level = 5

            criticality_score = impact * exposure_level  # 1..25

            if criticality_score >= 20:
                level = "critical"
            elif criticality_score >= 14:
                level = "high"
            elif criticality_score >= 8:
                level = "medium"
            else:
                level = "low"

            matrix[level] += 1
            matrix["items"].append({
                "ip": a["ip"],
                "zone": zone,
                "classification": a["classification"],
                "impact": impact,
                "exposure_level": exposure_level,
                "risk_score": a["risk_score"],
                "criticality_score": criticality_score,
                "criticality_level": level
            })

        # tri décroissant
        matrix["items"].sort(key=lambda x: x["criticality_score"], reverse=True)
        return matrix


    # ======================================================
    # ATTACK PATH SIMULATION (on the logical graph)
    # ======================================================
    def simulate_attack_paths(self, assets):
        """
        On construit un graphe logique basé sur les liens déjà utilisés :
        - DC -> Windows
        - Web -> DB
        - (option) DMZ -> LAN : si DMZ host existe et LAN host existe, lien "pivot"
        Puis on cherche des chemins "DMZ Web -> DB -> DC" etc.
        """
        # index par type
        dc = [a for a in assets if a["classification"] == "Domain Controller"]
        win = [a for a in assets if a["classification"] == "Windows Server"]
        web = [a for a in assets if a["classification"] == "Web Server"]

        # DB = host qui expose 3306/5432 (déduit des services)
        def is_db(a):
            for s in a.get("services", []):
                try:
                    if int(s["port"]) in (3306, 5432):
                        return True
                except Exception:
                    pass
            return False

        db = [a for a in assets if is_db(a)]
        dmz = [a for a in assets if a["zone"] != "LAN"]
        lan = [a for a in assets if a["zone"] == "LAN"]

        # graphe adjacency
        adj = {}
        def add_edge(u, v, reason):
            adj.setdefault(u, [])
            adj[u].append((v, reason))

        # liens connus
        for d in dc:
            for w in win:
                add_edge(d["ip"], w["ip"], "AD/DC → Windows")
                add_edge(w["ip"], d["ip"], "Windows → AD/DC (auth)")

        for w in web:
            for dbase in db:
                add_edge(w["ip"], dbase["ip"], "Web → DB")
                add_edge(dbase["ip"], w["ip"], "DB → Web (app dep)")

        # pivot DMZ -> LAN (heuristique)
        # si tu as au moins un host DMZ, on suppose qu’un pivot est possible vers des services admin exposés
        # (ça simule un scénario de compromission web en DMZ puis accès interne)
        for x in dmz:
            for y in lan:
                # lien seulement si y expose ports "admin" (22/3389/445)
                admin_ports = {22, 3389, 445}
                ok = False
                for s in y.get("services", []):
                    try:
                        if int(s["port"]) in admin_ports:
                            ok = True
                            break
                    except Exception:
                        pass
                if ok:
                    add_edge(x["ip"], y["ip"], "DMZ pivot → LAN admin surface")

        # BFS paths helper
        def find_paths(starts, targets, max_depth=5):
            paths = []
            target_set = set(t["ip"] for t in targets)

            for s in starts:
                start = s["ip"]
                q = [(start, [start], [])]  # node, path, reasons
                visited_depth = {start: 0}

                while q:
                    node, path, reasons = q.pop(0)
                    if len(path) > max_depth:
                        continue

                    if node in target_set and node != start:
                        paths.append({"path": path, "reasons": reasons})
                        continue

                    for (nxt, reason) in adj.get(node, []):
                        # éviter loops
                        if nxt in path:
                            continue
                        q.append((nxt, path + [nxt], reasons + [reason]))

            return paths

        # scenarios utiles
        scenarios = []

        # 1) DMZ -> DC
        if dmz and dc:
            p = find_paths(dmz, dc, max_depth=6)
            scenarios.append({"name": "DMZ compromise → Domain Controller", "paths": p})

        # 2) Web -> DB
        if web and db:
            p = find_paths(web, db, max_depth=3)
            scenarios.append({"name": "Web compromise → Database access", "paths": p})

        # 3) DMZ Web -> DB -> DC
        if dmz and db and dc:
            p1 = find_paths(dmz, db, max_depth=4)
            p2 = find_paths(db, dc, max_depth=4)
            combined = []
            # combine the first leg end == db start
            for a in p1:
                for b in p2:
                    if a["path"][-1] == b["path"][0]:
                        combined.append({
                            "path": a["path"] + b["path"][1:],
                            "reasons": a["reasons"] + b["reasons"]
                        })
            scenarios.append({"name": "DMZ pivot → DB → Domain Controller", "paths": combined})

        # garder uniquement chemins uniques (par path string)
        for sc in scenarios:
            uniq = {}
            for p in sc["paths"]:
                key = "->".join(p["path"])
                uniq[key] = p
            sc["paths"] = list(uniq.values())[:25]  # limite

        return scenarios

    # ======================================================
    # EXPORT
    # ======================================================
    def generate_outputs(self, assets, output_dir):

        # =========================
        # BASIC INVENTORY EXPORT
        # =========================
        json_file = output_dir / "inventory.json"
        csv_file = output_dir / "inventory.csv"
        traceroute_file = output_dir / "traceroutes.json"

        with open(json_file, "w") as f:
            json.dump(assets, f, indent=4)

        with open(csv_file, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP", "Zone", "Type", "Risk Score"])

            for asset in assets:
                writer.writerow([
                    asset["ip"],
                    asset["zone"],
                    asset["classification"],
                    asset["risk_score"]
                ])

        with open(traceroute_file, "w") as f:
            traceroutes = {a["ip"]: a.get("trace_path") for a in assets if a.get("trace_path")}
            json.dump(traceroutes, f, indent=4)

        # =========================
        # NEW ADVANCED ANALYTICS
        # =========================
        exposure = self.compute_exposure_by_zone(assets)
        criticality = self.compute_criticality_matrix(assets, exposure)
        attack_paths = self.simulate_attack_paths(assets)

        # -------------------------
        # JSON EXPORTS
        # -------------------------
        with open(output_dir / "exposure_by_zone.json", "w") as f:
            json.dump(exposure, f, indent=4)

        with open(output_dir / "criticality_matrix.json", "w") as f:
            json.dump(criticality, f, indent=4)

        with open(output_dir / "attack_paths.json", "w") as f:
            json.dump(attack_paths, f, indent=4)

        # -------------------------
        # CSV EXPOSURE EXPORT
        # -------------------------
        with open(output_dir / "exposure_by_zone.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "Zone",
                "Hosts",
                "Open Services",
                "Risky Ports",
                "Exposure Score",
                "Exposure Avg"
            ])

            for z, v in exposure.items():
                writer.writerow([
                    z,
                    v.get("hosts", 0),
                    v.get("open_services_total", 0),
                    v.get("risky_ports_total", 0),
                    v.get("exposure_score", 0),
                    v.get("exposure_score_avg", 0)
                ])

        # -------------------------
        # CSV CRITICALITY EXPORT (TOP 50)
        # -------------------------
        with open(output_dir / "criticality_top.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "IP",
                "Zone",
                "Type",
                "Impact",
                "Exposure",
                "Risk Score",
                "Criticality Score",
                "Level"
            ])

            for item in criticality.get("items", [])[:50]:
                writer.writerow([
                    item.get("ip"),
                    item.get("zone"),
                    item.get("classification"),
                    item.get("impact"),
                    item.get("exposure_level"),
                    item.get("risk_score"),
                    item.get("criticality_score"),
                    item.get("criticality_level")
                ])

        console.print("[+] Advanced analytics exports generated.")

    # ======================================================
    # HTML INTERACTIVE MAP
    # ======================================================
    def generate_html_map(self, assets, output_dir):
        html_file = output_dir / "topology.html"

        static_dir = self.plugin_base / "static"
        static_dir.mkdir(exist_ok=True)

        exposure = self.compute_exposure_by_zone(assets)
        criticality = self.compute_criticality_matrix(assets, exposure)
        attack_paths = self.simulate_attack_paths(assets)

        nodes = []
        edges = []
        edge_ids = 0

        db_ports = [3306, 5432]

        # nodes
        for asset in assets:
            color = (
                "#ff4c4c" if asset["risk_score"] >= 7
                else "#ffae42" if asset["risk_score"] >= 4
                else "#4caf50"
            )
            nodes.append({
                "id": asset["ip"],
                "label": asset["ip"],
                "group": asset["zone"],
                "color": color,
                "type": asset["classification"],
                "risk": asset["risk_score"],
                "services": [s.get("port") for s in asset.get("services", [])],
                "title": (
                    f"IP: {asset['ip']}\n"
                    f"Zone: {asset['zone']}\n"
                    f"Type: {asset['classification']}\n"
                    f"Risk Score: {asset['risk_score']}\n"
                    f"Services: {', '.join(str(s.get('port')) for s in asset.get('services', []))}"
                )
            })

        # edges logic
        for a in assets:
            for b in assets:
                if a["ip"] == b["ip"]:
                    continue

                if a["classification"] == "Domain Controller" and b["classification"] == "Windows Server":
                    edge_ids += 1
                    edges.append({
                        "id": f"e{edge_ids}",
                        "from": a["ip"], "to": b["ip"],
                        "label": "AD",
                        "dashes": True,
                        "color": {"color": "#888"}
                    })

                if a["classification"] == "Web Server":
                    is_db = False
                    for svc in b.get("services", []):
                        try:
                            if int(svc["port"]) in db_ports:
                                is_db = True
                                break
                        except Exception:
                            pass
                    if is_db:
                        edge_ids += 1
                        edges.append({
                            "id": f"e{edge_ids}",
                            "from": a["ip"], "to": b["ip"],
                            "label": "DB",
                            "color": {"color": "#00bcd4"}
                        })

        # traceroute
        known_node_ids = set(n["id"] for n in nodes)

        # traceroute nodes
        def add_hop_node(ip_):
            if ip_ in known_node_ids:
                return
            known_node_ids.add(ip_)
            nodes.append({
                "id": ip_,
                "label": ip_,
                "group": "PATH",
                "color": "#b0bec5",
                "type": "Router / Hop",
                "risk": 0,
                "services": [],
                "title": f"Traceroute hop: {ip_}"
            })

        # traceroute edges
        for a in assets:
            path = a.get("trace_path")
            if not path or len(path) < 2:
                continue

            for hop_ip in path[:-1]:
                add_hop_node(hop_ip)

            for i in range(0, len(path) - 1):
                frm = path[i]
                to = path[i+1]
                edge_ids += 1
                edges.append({
                    "id": f"e{edge_ids}",
                    "from": frm,
                    "to": to,
                    "label": "TR",
                    "dashes": True,
                    "color": {"color": "#9aa0a6"},
                    "traceroute": True,
                    "hidden": True
                })

        trace_paths = {
            a["ip"]: a.get("trace_path")
            for a in assets
            if a.get("trace_path")
        }

        # Add edges
        def has_port(asset, port):
            for s in asset.get("services", []):
                try:
                    if int(s.get("port", -1)) == port:
                        return True
                except:
                    pass
            return False

        def add_edge(frm, to, label, color="#666", dashes=False):
            nonlocal edge_ids
            edge_ids += 1
            edges.append({
                "id": f"e{edge_ids}",
                "from": frm,
                "to": to,
                "label": label,
                "dashes": dashes,
                "color": {"color": color},
                "hidden": False
            })

        dns_servers = [a for a in assets if has_port(a, 53)]
        web_servers = [a for a in assets if has_port(a, 80) or has_port(a, 443)]
        smb_servers = [a for a in assets if has_port(a, 445)]
        ssh_servers = [a for a in assets if has_port(a, 22)]
        rdp_servers = [a for a in assets if has_port(a, 3389)]

        clients = [a for a in assets if a["classification"] in ("Workstation / Unknown", "Windows")]

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
                        "id": f"e{edge_ids}",
                        "from": a["ip"],
                        "to": t["ip"],
                        "label": "SSH",
                        "dashes": True,
                        "color": {"color": "#4caf50"},
                        "admin": True,
                        "hidden": True
                    })

            for t in rdp_servers:
                if a["ip"] != t["ip"]:
                    edge_ids += 1
                    edges.append({
                        "id": f"e{edge_ids}",
                        "from": a["ip"],
                        "to": t["ip"],
                        "label": "RDP",
                        "dashes": True,
                        "color": {"color": "#ff9800"},
                        "admin": True,
                        "hidden": True
                    })

        html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <title>Advanced SI Mapping</title>
    <script src="../../../static/vis-network.min.js"></script>

    <style>
    body {{
    background: #0f111a;
    color: white;
    font-family: Arial;
    margin: 0;
    }}
    .wrapper {{
    display: grid;
    grid-template-columns: 320px 1fr;
    height: 100vh;
    }}
    .sidebar {{
    border-right: 1px solid #333;
    padding: 12px;
    overflow: auto;
    background: #0c0e16;
    }}
    #network {{
    width: 100%;
    height: 100vh;
    background: #1a1d2b;
    }}
    h2,h3 {{ margin: 8px 0; }}
    .small {{ font-size: 12px; color: #bbb; }}
    button {{
    background: #222;
    color: white;
    border: 1px solid #555;
    padding: 6px 10px;
    margin: 4px 4px 4px 0;
    cursor: pointer;
    }}
    select {{
    width: 100%;
    padding: 6px;
    background: #141828;
    color: white;
    border: 1px solid #444;
    }}
    .table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    }}
    .table td, .table th {{
    border-bottom: 1px solid #222;
    padding: 6px 4px;
    }}
    .badge {{
    display: inline-block;
    padding: 2px 6px;
    border: 1px solid #444;
    border-radius: 999px;
    font-size: 11px;
    }}
    .badge.critical {{ border-color:#ff4c4c; color:#ff4c4c; }}
    .badge.high {{ border-color:#ffae42; color:#ffae42; }}
    .badge.medium {{ border-color:#8bc34a; color:#8bc34a; }}
    .badge.low {{ border-color:#90a4ae; color:#90a4ae; }}
    .vis-navigation .vis-button {{
        width: 52px !important;
        height: 52px !important;
        border-radius: 14px !important;
        background: linear-gradient(145deg, #1f2438, #151927) !important;
        border: 1px solid rgba(255,255,255,0.12) !important;
        box-shadow: 0 8px 25px rgba(0,0,0,0.5);
        display: flex !important;
        align-items: center;
        justify-content: center;
        transition: 0.2s ease;
    }}
    .vis-navigation .vis-button:hover {{
        transform: translateY(-2px);
        box-shadow: 0 12px 35px rgba(0,0,0,0.6);
    }}
    .vis-navigation .vis-up,
    .vis-navigation .vis-down,
    .vis-navigation .vis-right,
    .vis-navigation .vis-left {{
        position: absolute !important;
        bottom: 25px !important;
        left: 82px !important;
    }}
    .vis-navigation .vis-zoomIn,
    .vis-navigation .vis-zoomOut,
    .vis-navigation .vis-zoomExtends {{
        position: absolute !important;
        bottom: 25px !important;
        right: 82px !important;
    }}
    .vis-navigation .vis-up{{
        bottom: 82px !important;
    }}
    .vis-navigation .vis-left{{
        left: 25px !important;
    }}
    .vis-navigation .vis-right {{
        left: 139px !important;
    }}
    .vis-navigation .vis-zoomIn{{
        right: 139px !important;
    }}
    .vis-navigation .vis-zoomExtends {{
        right: 25px !important;
    }}
    body.redteam #network {{ background: #140b0b; }}
    body.redteam .sidebar {{ background: #0f0707; }}
    body.redteam button {{ border-color: rgba(255,76,76,0.4); }}
    </style>
    </head>

    <body>
    <div class="wrapper">
    <div class="sidebar">
        <h2>SI Analytics</h2>

        <h3>Filters</h3>

        <h4>Nodes</h4>
        <button onclick="filterType('all')">All</button>
        <button onclick="filterType('Domain Controller')">DC</button>
        <button onclick="filterType('Windows Server')">Windows Server</button>
        <button onclick="filterType('Windows')">Windows</button>
        <button onclick="filterType('Web Server')">Web</button>
        <button onclick="filterType('Database Server')">DB</button>

        <h4>Link Filters</h4>
        <button onclick="toggleAllLinks()" id="allLinksBtn">Show All Links</button>
        <button onclick="toggleLink('TR')">TraceRoute</button>
        <button onclick="toggleLink('AD')">AD</button>
        <button onclick="toggleLink('DB')">DB</button>
        <button onclick="toggleLink('DNS')">DNS</button>
        <button onclick="toggleLink('HTTP')">HTTP</button>
        <button onclick="toggleLink('SMB')">SMB</button>
        <button onclick="toggleLink('SSH')">SSH</button>
        <button onclick="toggleLink('RDP')">RDP</button>
        
        <h4>Visuals</h4>
        <button onclick="toggleTeamMode()" id="teamBtn">Mode: Blue Team</button>
        <button onclick="toggleHeatmap()" id="heatToggleBtn">Heatmap: OFF</button>
        <button onclick="clusterZone('LAN')">Collapse LAN</button>
        <button onclick="clusterZone('DMZ / External')">Collapse DMZ</button>
        <button onclick="expandAllClusters()">Expand All</button>
        
        <h3>Attack</h3>

        <h4>Attack Simulation</h4>
        <select id="attackStart"></select>
        <button onclick="startAttackSim()">Start</button>
        <button onclick="stopAttackSim()">Stop</button>
        
        <h4>Traceroute</h4>
        <select id="traceTarget"></select>
        <button onclick="showTraceToTarget()">Show</button>
        <button onclick="hideAllTraceroutes()">Hide</button>

        <h4>Export</h4>
        <button onclick="exportPNG()">Export PNG</button>

        <h3>Exposure by zone</h3>
        <div class="small">Heuristic exposure score (services + risky ports + DMZ bonus)</div>
        <table class="table" id="exposureTable"></table>

        <h3>Criticality matrix</h3>
        <div>
        <span class="badge critical">critical: {criticality["critical"]}</span>
        <span class="badge high">high: {criticality["high"]}</span>
        <span class="badge medium">medium: {criticality["medium"]}</span>
        <span class="badge low">low: {criticality["low"]}</span>
        </div>

        <h3>Attack paths</h3>
        <div class="small">Simulated logical paths (not proven flows)</div>
        <select id="pathSelect" onchange="selectPath()"></select>
        <button onclick="clearPath()">Clear highlight</button>

        <h3>Top critical assets</h3>
        <table class="table" id="critTable"></table>
    </div>

    <div id="network"></div>
    </div>

    <script>
    function svgDataUri(svg) {{
        return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
    }}

    const ICONS = {{
        windows: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
            <rect x="4" y="6" width="26" height="24" fill="#4FC3F7"/><rect x="34" y="6" width="26" height="24" fill="#29B6F6"/>
            <rect x="4" y="34" width="26" height="24" fill="#29B6F6"/><rect x="34" y="34" width="26" height="24" fill="#0288D1"/>
        </svg>`),

        linux: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
            <circle cx="32" cy="20" r="10" fill="#ECEFF1"/><ellipse cx="32" cy="42" rx="16" ry="18" fill="#263238"/>
            <circle cx="28" cy="18" r="2" fill="#000"/><circle cx="36" cy="18" r="2" fill="#000"/>
            <ellipse cx="32" cy="26" rx="5" ry="3" fill="#FFC107"/>
        </svg>`),

        router: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
            <rect x="10" y="26" width="44" height="22" rx="6" fill="#90A4AE"/>
            <circle cx="22" cy="37" r="3" fill="#00E676"/><circle cx="32" cy="37" r="3" fill="#FFD600"/><circle cx="42" cy="37" r="3" fill="#FF5252"/>
            <path d="M20 26 C22 14, 28 12, 32 10" stroke="#B0BEC5" stroke-width="3" fill="none"/>
            <path d="M44 26 C42 14, 36 12, 32 10" stroke="#B0BEC5" stroke-width="3" fill="none"/>
        </svg>`),

        web: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
            <rect x="10" y="10" width="44" height="44" rx="10" fill="#00BCD4"/>
            <path d="M18 30h28M18 38h28" stroke="#00323a" stroke-width="4"/>
            <circle cx="24" cy="24" r="3" fill="#00323a"/>
            <circle cx="32" cy="24" r="3" fill="#00323a"/>
            <circle cx="40" cy="24" r="3" fill="#00323a"/>
        </svg>`),

        unknown: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
            <rect x="10" y="14" width="44" height="30" rx="6" fill="#78909C"/>
            <rect x="26" y="46" width="12" height="6" fill="#546E7A"/>
            <text x="32" y="36" font-size="22" text-anchor="middle" fill="#ECEFF1">?</text>
        </svg>`)
    }};

    function iconForType(t) {{
        if (t === "Windows" || t === "Windows Server") return ICONS.windows;
        if (t === "Linux Server") return ICONS.linux;
        if (t === "Router / Gateway") return ICONS.router;
        if (t === "Web Server") return ICONS.web;
        return ICONS.unknown;
    }}

    var allNodes = {json.dumps(nodes)};
    allNodes = allNodes.map(n => {{
        n.shape = "image";
        n.image = iconForType(n.type);
        n.size = 28;
        n.borderWidth = 2;
        return n;
    }});

    var allEdges = {json.dumps(edges)};
    var exposure = {json.dumps(exposure)};
    var criticality = {json.dumps(criticality)};
    var attackPaths = {json.dumps(attack_paths)};
    var tracePaths = {json.dumps(trace_paths)};

    var container = document.getElementById('network');

    var nodes = new vis.DataSet(allNodes);
    var edges = new vis.DataSet(allEdges);

    var data = {{ nodes: nodes, edges: edges }};

    var options = {{
        layout: {{
            improvedLayout: true,
            randomSeed: 2
        }},
        physics: {{
            enabled: true,
            solver: "forceAtlas2Based",
            forceAtlas2Based: {{
                gravitationalConstant: -50,
                centralGravity: 0.005,
                springLength: 100,
                springConstant: 0.04,
                damping: 0.9,
                avoidOverlap: 1
            }},
            stabilization: {{
                iterations: 1500
            }}
        }},
        interaction: {{
            hover: true,
            dragNodes: true,
            dragView: true,
            zoomView: true,
            navigationButtons: true,
            keyboard: {{
                enabled: true,
                speed: {{ x: 10, y: 10, zoom: 0.02 }},
                bindToWindow: false
            }},
            zoomSpeed: 0.6
            }},
        nodes: {{
            shape: "dot",
            size: 22,
            font: {{
                color: "white",
                size: 14,
                strokeWidth: 3,
                strokeColor: "#000"
            }}
        }},
        edges: {{
            smooth: {{
                type: "dynamic"
            }},
            width: 1.5
        }},
        groups: {{
            "LAN": {{ color: {{ background: "#1e88e5" }} }},
            "DMZ / External": {{ color: {{ background: "#e53935" }} }},
            "PATH": {{ color: {{ background: "#607d8b" }} }}
        }}
    }};

    var network = new vis.Network(container, data, options);

    edges.update(
        allEdges
            .filter(e => e.id)
            .map(e => ({{
                id: e.id,
                hidden: true
            }}))
    );

    network.on("afterDrawing", function () {{
        if (!network.canvas.body.container.style.cursor) {{
            network.canvas.body.container.style.cursor = "grab";
        }}
    }});
    network.on("hoverNode", function(params) {{
        network.canvas.body.container.style.cursor = "pointer";
    }});
    network.setOptions({{
        interaction: {{ hover: true }},
    }});
    network.once("stabilizationIterationsDone", function () {{
        network.setOptions({{ physics: false }});
    }});

    setTimeout(() => {{
        const map = {{
            "vis-up": "Up",
            "vis-down": "Down",
            "vis-left": "Left",
            "vis-right": "Right",
            "vis-zoomIn": "Zoom in",
            "vis-zoomOut": "Zoom out",
            "vis-zoomExtends": "Fit"
        }};

        Object.keys(map).forEach(cls => {{
            const el = document.querySelector("." + cls);
            if (el) el.title = map[cls];
        }});
    }}, 200);

    edges.update(
        allEdges
            .filter(e => e.id)
            .map(e => ({{
                id: e.id,
                hidden: true
            }}))
    );

    function injectNavIcons() {{
        const icons = {{
            "vis-up": "▲",
            "vis-down": "▼",
            "vis-left": "◀",
            "vis-right": "▶",
            "vis-zoomIn": "+",
            "vis-zoomOut": "−",
            "vis-zoomExtends": "⤢"
        }};

        Object.keys(icons).forEach(cls => {{
            const el = document.querySelector("." + cls);
            if (el) {{
                el.innerHTML = `<span style="font-size:20px;color:white;">${{icons[cls]}}</span>`;
            }}
        }});
    }}

    setTimeout(injectNavIcons, 400);

    // ---------- UI tables ----------
    function renderExposure() {{
    var html = "<tr><th>Zone</th><th>Hosts</th><th>Open</th><th>Risky</th><th>Avg</th></tr>";
    Object.keys(exposure).forEach(z => {{
        var v = exposure[z];
        html += `<tr>
        <td>${{z}}</td>
        <td>${{v.hosts}}</td>
        <td>${{v.open_services_total}}</td>
        <td>${{v.risky_ports_total}}</td>
        <td>${{v.exposure_score_avg}}</td>
        </tr>`;
    }});
    document.getElementById("exposureTable").innerHTML = html;
    }}

    function renderCriticalTop() {{
    var html = "<tr><th>IP</th><th>Type</th><th>Zone</th><th>Score</th><th>Lvl</th></tr>";
    criticality.items.slice(0, 10).forEach(it => {{
        html += `<tr>
        <td>${{it.ip}}</td>
        <td>${{it.classification}}</td>
        <td>${{it.zone}}</td>
        <td>${{it.criticality_score}}</td>
        <td>${{it.criticality_level}}</td>
        </tr>`;
    }});
    document.getElementById("critTable").innerHTML = html;
    }}

    function fillPathSelect() {{
    var sel = document.getElementById("pathSelect");
    sel.innerHTML = "";
    var idx = 0;

    attackPaths.forEach(sc => {{
        sc.paths.forEach(p => {{
        var label = sc.name + " | " + p.path.join(" -> ");
        var opt = document.createElement("option");
        opt.value = idx;
        opt.textContent = label;
        opt.dataset.scenario = sc.name;
        opt.dataset.path = JSON.stringify(p.path);
        opt.dataset.reasons = JSON.stringify(p.reasons);
        sel.appendChild(opt);
        idx++;
        }});
    }});

    if (sel.options.length === 0) {{
        var opt = document.createElement("option");
        opt.textContent = "No paths found";
        opt.value = "";
        sel.appendChild(opt);
    }}
    }}

    renderExposure();
    renderCriticalTop();
    fillPathSelect();

    // ---------- Filtering ----------
    // ---------- Filters ----------
    var currentFilter = "all";
    function filterType(type) {{
        currentFilter = type;
        var nodeUpdates = [];
        var visibleNodeIds = new Set();

        allNodes.forEach(n => {{
            var show = (type === "all") || (n.type === type);

            nodeUpdates.push({{
            id: n.id,
            hidden: !show
            }});

            if (show) visibleNodeIds.add(n.id);
        }});

        nodes.update(nodeUpdates);
        network.redraw();

        var edgeUpdates = [];

        allEdges.forEach(e => {{
            var showEdge =
            visibleNodeIds.has(e.from) &&
            visibleNodeIds.has(e.to);

            edgeUpdates.push({{
            id: e.id,
            hidden: !showEdge
            }});
        }});

        edges.update(edgeUpdates);

        setTimeout(() => {{
            network.fit({{
            animation: {{
                duration: 500,
                easingFunction: "easeInOutQuad"
            }}
            }});
        }}, 200);
    }}

    // ---------- Show All Links ----------
    var allLinksVisible = false;
    function toggleAllLinks() {{
        allLinksVisible = !allLinksVisible;

        edges.update(
            allEdges
                .filter(e => e.id)
                .map(e => ({{
                    id: e.id,
                    hidden: !allLinksVisible
                }}))
        );

        document.getElementById("allLinksBtn").innerText =
            allLinksVisible ? "Hide All Links" : "Show All Links";
    }}

    // ---------- Links Filters ----------
    var activeLinks = {{}};

    function toggleLink(label) {{
        let currentlyVisible = false;

        allEdges.forEach(e => {{
            if (e.label === label) {{
                const current = edges.get(e.id);
                if (current && current.hidden === false) {{
                    currentlyVisible = true;
                }}
            }}
        }});

        const newState = currentlyVisible; // si visible → on cache

        const updates = [];

        allEdges.forEach(e => {{
            if (e.label === label) {{
                updates.push({{
                    id: e.id,
                    hidden: newState
                }});
            }}
        }});

        edges.update(updates);
    }}

    // ---------- Red/Blue Team ----------
    var redTeam = false;

    function toggleTeamMode() {{
        redTeam = !redTeam;
        document.body.classList.toggle("redteam", redTeam);

        document.getElementById("teamBtn").innerText =
            redTeam ? "Mode: Red Team" : "Mode: Blue Team";
    }}

    // ---------- Heatmap ----------
    var heatmapOn = false;

    var baseNodeColors = {{}};
    allNodes.forEach(n => baseNodeColors[n.id] = n.color);

    function riskColor(risk) {{
        // 0..10 -> green -> orange -> red
        if (risk >= 7) return "#ff4c4c";
        if (risk >= 4) return "#ffae42";
        return "#4caf50";
    }}

    function toggleHeatmap() {{
        heatmapOn = !heatmapOn;

        var updated = [];

        allNodes.forEach(n => {{

            var visible =
                (currentFilter === "all") ||
                (n.type === currentFilter);

            if (!visible) return;

            updated.push({{
                id: n.id,
                color: heatmapOn
                    ? riskColor(n.risk || 0)
                    : (baseNodeColors[n.id] || n.color)
            }});
        }});

        nodes.update(updated);

        document.getElementById("heatToggleBtn").innerText =
            heatmapOn ? "Heatmap: ON" : "Heatmap: OFF";
    }}

    // ---------- Cluster ----------
    var clustered = {{ "LAN": false, "DMZ / External": false }};

    function clusterZone(zoneName) {{
        if (clustered[zoneName]) return;

        network.cluster({{
            joinCondition: function (nodeOptions) {{
            return nodeOptions.group === zoneName;
            }},
            clusterNodeProperties: {{
            id: "cluster_" + zoneName,
            label: zoneName + " (cluster)",
            shape: "database",
            color: {{ background: "#111827", border: "#374151" }},
            font: {{ color: "white" }}
            }}
        }});

        clustered[zoneName] = true;
        }}

        function expandAllClusters() {{
        Object.keys(clustered).forEach(z => {{
            const cid = "cluster_" + z;
            if (network.isCluster(cid)) network.openCluster(cid);
            clustered[z] = false;
        }});
    }}

    // ---------- Attack ----------
    // ---------- Attack Sim ----------
    setTimeout(() => {{
        const sel = document.getElementById("attackStart");
        sel.innerHTML = "";
        allNodes.forEach(n => {{
            const o = document.createElement("option");
            o.value = n.id;
            o.textContent = n.id + " (" + n.type + ")";
            sel.appendChild(o);
        }});
    }}, 100);

    var attackTimers = [];
    var attackRunning = false;

    function stopAttackSim() {{
        attackRunning = false;
        attackTimers.forEach(t => clearTimeout(t));
        attackTimers = [];
        clearPath(); // reuse your existing reset
    }}

    function startAttackSim() {{

        stopAttackSim();
        attackRunning = true;

        const start = document.getElementById("attackStart").value;
        if (!start) return;

        const visibleNodes = new Set();

        allNodes.forEach(n => {{
            var visible =
                (currentFilter === "all") ||
                (n.type === currentFilter);

            if (visible) visibleNodes.add(n.id);
        }});

        if (!visibleNodes.has(start)) {{
            alert("Selected node is not visible in current filter.");
            return;
        }}

        const adj = {{}};

        allEdges.forEach(e => {{

            if (
                visibleNodes.has(e.from) &&
                visibleNodes.has(e.to) &&
                !e.hidden
            ) {{
                adj[e.from] = adj[e.from] || [];
                adj[e.to] = adj[e.to] || [];

                adj[e.from].push({{ n: e.to, id: e.id }});
                adj[e.to].push({{ n: e.from, id: e.id }});
            }}
        }});

        const visited = new Set([start]);
        const q = [{{ node: start, depth: 0 }}];
        const stepDelay = 450;

        function highlightNode(id) {{
            nodes.update({{
                id,
                borderWidth: 4,
                color: "#ff4c4c"
            }});
        }}

        function highlightEdge(eid) {{
            edges.update({{
                id: eid,
                color: {{ color: "#ff4c4c" }},
                width: 4,
                dashes: false
            }});
            highlightedEdgeIds.push(eid);
        }}

        let step = 0;

        while (q.length) {{

            const cur = q.shift();
            const neigh = adj[cur.node] || [];

            neigh.forEach(x => {{

                if (visited.has(x.n)) return;

                visited.add(x.n);
                q.push({{ node: x.n, depth: cur.depth + 1 }});

                const t = setTimeout(() => {{
                    if (!attackRunning) return;
                    highlightEdge(x.id);
                    highlightNode(x.n);
                }}, step * stepDelay);

                attackTimers.push(t);
                step++;
            }});
        }}

        network.focus(start, {{ scale: 1.25 }});
        highlightNode(start);
    }}

    // ---------- Traceroute ----------
    setTimeout(() => {{
        const sel = document.getElementById("traceTarget");
        sel.innerHTML = "";
        allNodes
            .filter(n => n.type !== "Router / Hop")
            .forEach(n => {{
            const o = document.createElement("option");
            o.value = n.id;
            o.textContent = n.id + " (" + n.type + ")";
            sel.appendChild(o);
            }});
        }}, 120);
    
    function hideAllTraceroutes() {{
        edges.update(
            allEdges
            .filter(e => e.label === "TR")
            .map(e => ({{ id: e.id, hidden: true }}))
        );
    }}

    function showTraceToTarget() {{
        const target = document.getElementById("traceTarget").value;
        if (!target) return;

        hideAllTraceroutes();

        const path = tracePaths[target];
        if (!path || path.length < 2) {{
            alert("No traceroute path for this target.");
            return;
        }}

        // on construit les paires hop -> hop suivant
        const pairs = new Set();
        for (let i = 0; i < path.length - 1; i++) {{
            pairs.add(path[i] + "->" + path[i+1]);
            pairs.add(path[i+1] + "->" + path[i]); // sécurité si edge inversé
        }}

        const updates = [];

        allEdges.forEach(e => {{

            if (e.label !== "TR") return;

            const key = e.from + "->" + e.to;

            if (pairs.has(key)) {{
                updates.push({{
                    id: e.id,
                    hidden: false,
                    width: 3,
                    dashes: false,
                    color: {{ color: "#ff9800" }}
                }});
            }}
        }});

        edges.update(updates);

        network.focus(target, {{ scale: 1.2 }});
    }}
    
    // ---------- Export PNG ----------
    function exportPNG() {{
        const visibleNodes = new Set();

        allNodes.forEach(n => {{
            var visible =
                (currentFilter === "all") ||
                (n.type === currentFilter);

            if (visible) visibleNodes.add(n.id);
        }});

        const nodeStateBackup = [];
        const edgeStateBackup = [];

        allNodes.forEach(n => {{
            nodeStateBackup.push({{
                id: n.id,
                hidden: nodes.get(n.id).hidden
            }});
        }});

        allEdges.forEach(e => {{
            edgeStateBackup.push({{
                id: e.id,
                hidden: edges.get(e.id).hidden
            }});
        }});

        nodes.update(
            allNodes.map(n => ({{
                id: n.id,
                hidden: !visibleNodes.has(n.id)
            }}))
        );

        edges.update(
            allEdges.map(e => ({{
                id: e.id,
                hidden: !(visibleNodes.has(e.from) && visibleNodes.has(e.to))
            }}))
        );

        network.fit();

        setTimeout(() => {{

            var canvas = document.querySelector("canvas");
            var link = document.createElement("a");
            link.href = canvas.toDataURL("image/png");
            link.download = "si_mapping_filtered.png";
            link.click();

            nodes.update(nodeStateBackup);

            edges.update(edgeStateBackup);

            network.fit();

        }}, 400);
    }}

    // ---------- Attack path highlighting ----------
    var highlightedEdgeIds = [];
    function clearPath() {{
        highlightedEdgeIds.forEach(eid => {{
            edges.update({{id: eid, color: {{color:"#888"}}, width: 1, dashes: false}});
        }});
        highlightedEdgeIds = [];
    }}

    function selectPath() {{
        clearPath();
        var sel = document.getElementById("pathSelect");
        if (!sel.value) return;

        var opt = sel.options[sel.selectedIndex];
        var path = JSON.parse(opt.dataset.path);
        var reasons = JSON.parse(opt.dataset.reasons);

        for (var i=0; i<path.length-1; i++) {{
            var u = path[i], v = path[i+1];

            allEdges.forEach(e => {{
            if ((e.from === u && e.to === v) || (e.from === v && e.to === u)) {{
                highlightedEdgeIds.push(e.id);
                edges.update({{id: e.id, color: {{color:"#ff4c4c"}}, width: 4, dashes: false}});
            }}
        }});
    }}

    network.focus(path[0], {{scale: 1.2}});
    }}

    </script>
    </body>
    </html>
    """

        with open(html_file, "w") as f:
            f.write(html_content)

        console.print(f"[+] Advanced interactive map generated: {html_file}")

    # ======================================================
    # GLOBAL SI SCORE
    # ======================================================
    def compute_global_score(self, assets, criticality):
        """
        Score global sur 100
        basé sur :
        - moyenne risk_score
        - % d'assets critiques
        - exposition DMZ
        """

        if not assets:
            return 100

        avg_risk = sum(a["risk_score"] for a in assets) / len(assets)

        total = len(assets)
        critical_assets = criticality["critical"] + criticality["high"]

        critical_ratio = critical_assets / total

        score = 100
        score -= avg_risk * 5
        score -= critical_ratio * 40

        return max(round(score, 2), 0)

    # ======================================================
    # AUTO SUMMARY
    # ======================================================
    def print_executive_summary(self, assets, exposure, criticality, global_score):

        console.rule("[bold red]EXECUTIVE SUMMARY[/bold red]")

        console.print(f"[bold white]Total assets discovered:[/bold white] {len(assets)}")
        console.print(f"[bold white]Critical assets:[/bold white] {criticality['critical']}")
        console.print(f"[bold white]High risk assets:[/bold white] {criticality['high']}")
        console.print(f"[bold white]Medium risk assets:[/bold white] {criticality['medium']}")
        console.print(f"[bold white]Low risk assets:[/bold white] {criticality['low']}")

        console.print()
        console.print(f"[bold yellow]Global Security Score:[/bold yellow] {global_score}/100")

        if global_score >= 80:
            console.print("[green]Security posture: GOOD[/green]")
        elif global_score >= 60:
            console.print("[yellow]Security posture: MODERATE[/yellow]")
        else:
            console.print("[red]Security posture: CRITICAL[/red]")

        console.rule()

    # ======================================================
    # EXECUTIVE REPORT (HTML)
    # ======================================================
    def generate_executive_report(self, assets, exposure, criticality, global_score, output_dir):

        report_file = output_dir / "executive_report.html"

        top5 = criticality["items"][:5]

        html = f"""
        <html>
        <head>
        <title>Executive Security Report</title>
        <style>
        body {{
            font-family: Arial;
            background:#0f111a;
            color:white;
            padding:40px;
        }}
        h1 {{ color:#ff4c4c; }}
        .score {{
            font-size:28px;
            margin:20px 0;
        }}
        table {{
            width:100%;
            border-collapse: collapse;
            margin-top:20px;
        }}
        td, th {{
            border-bottom:1px solid #333;
            padding:8px;
        }}
        </style>
        </head>
        <body>

        <h1>Information System Security Executive Report</h1>

        <div class="score">
        Global Security Score: <b>{global_score}/100</b>
        </div>

        <h2>Summary</h2>
        <ul>
            <li>Total assets discovered: {len(assets)}</li>
            <li>Critical assets: {criticality['critical']}</li>
            <li>High risk assets: {criticality['high']}</li>
            <li>Medium risk assets: {criticality['medium']}</li>
            <li>Low risk assets: {criticality['low']}</li>
        </ul>

        <h2>Top 5 Critical Assets</h2>
        <table>
        <tr><th>IP</th><th>Type</th><th>Zone</th><th>Criticality Score</th></tr>
        """

        for item in top5:
            html += f"""
            <tr>
                <td>{item['ip']}</td>
                <td>{item['classification']}</td>
                <td>{item['zone']}</td>
                <td>{item['criticality_score']}</td>
            </tr>
            """

        html += """
        </table>

        <h2>Recommendations</h2>
        <ul>
            <li>Reduce exposed administrative services (RDP, SSH, SMB).</li>
            <li>Segment DMZ from LAN strictly.</li>
            <li>Apply patch management on high critical assets.</li>
            <li>Restrict lateral movement paths.</li>
        </ul>

        </body>
        </html>
        """

        with open(report_file, "w") as f:
            f.write(html)

        console.print(f"[+] Executive report generated: {report_file}")

    # ======================================================
    # EXECUTIVE REPORT PDF
    # ======================================================
    def generate_pdf_report(self, assets, exposure, criticality, global_score, output_dir):

        pdf_path = output_dir / "executive_report.pdf"

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=pagesizes.A4
        )

        elements = []
        styles = getSampleStyleSheet()

        title_style = styles["Heading1"]
        normal_style = styles["Normal"]

        elements.append(Paragraph("Information System Security Executive Report", title_style))
        elements.append(Spacer(1, 8))

        elements.append(Paragraph(f"<b>Global Security Score:</b> {global_score}/100", styles["Heading2"]))
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("<b>Summary</b>", styles["Heading2"]))
        elements.append(Spacer(1, 6))

        summary_data = [
            ["Total assets", len(assets)],
            ["Critical assets", criticality["critical"]],
            ["High risk assets", criticality["high"]],
            ["Medium risk assets", criticality["medium"]],
            ["Low risk assets", criticality["low"]],
        ]

        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.black),
            ("TEXTCOLOR", (0,0), (-1,-1), colors.black),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("ALIGN", (1,0), (-1,-1), "CENTER"),
        ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 8))

        elements.append(Paragraph("<b>Exposure by Zone</b>", styles["Heading2"]))
        elements.append(Spacer(1, 6))

        exposure_data = [["Zone", "Hosts", "Open", "Risky", "Avg Score"]]

        for z, v in exposure.items():
            exposure_data.append([
                z,
                v["hosts"],
                v["open_services_total"],
                v["risky_ports_total"],
                v["exposure_score_avg"]
            ])

        exposure_table = Table(exposure_data, repeatRows=1)
        exposure_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("ALIGN", (1,1), (-1,-1), "CENTER"),
        ]))

        elements.append(exposure_table)
        elements.append(Spacer(1, 8))

        elements.append(Paragraph("<b>Top 10 Critical Assets</b>", styles["Heading2"]))
        elements.append(Spacer(1, 6))

        crit_data = [["IP", "Type", "Zone", "Score"]]

        for item in criticality["items"][:10]:
            crit_data.append([
                item["ip"],
                item["classification"],
                item["zone"],
                item["criticality_score"]
            ])

        crit_table = Table(crit_data, repeatRows=1)
        crit_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("ALIGN", (3,1), (3,-1), "CENTER"),
        ]))

        elements.append(crit_table)
        elements.append(Spacer(1, 8))

        elements.append(Paragraph("<b>Security Recommendations</b>", styles["Heading2"]))
        elements.append(Spacer(1, 6))

        recs = [
            "• Reduce exposed administrative services (RDP, SSH, SMB).",
            "• Strictly segment DMZ from LAN.",
            "• Apply patch management on high critical assets.",
            "• Monitor lateral movement paths."
        ]

        for r in recs:
            elements.append(Paragraph(r, normal_style))
            elements.append(Spacer(1, 4))

        elements.append(Spacer(1, 8))
        elements.append(Paragraph("<b>Interactive Topology Map</b>", styles["Heading2"]))
        elements.append(Spacer(1, 6))

        topology_path = output_dir / "topology.html"
        topology_abs = topology_path.resolve()

        topology_url = f"file:///{topology_abs}"

        link_style = ParagraphStyle(
            "link_style",
            parent=styles["Normal"],
            textColor=colors.blue,
            underline=True
        )

        elements.append(
            Paragraph(
                f'<link href="{topology_url}"><b>🌐Open Interactive Topology Map</b></link>',
                link_style
            )
        )

        doc.build(elements)

        console.print(f"[green][+] PDF report generated: {pdf_path}[/green]")

    # ======================================================
    # RUN MAPPING
    # ======================================================
    def run_mapping(self):
        client_folder = select_or_create_client_folder(self.results_base)
        if not client_folder:
            return

        existing_targets = []

        if client_folder.exists():
            for item in sorted(client_folder.iterdir()):
                if item.is_dir():
                    existing_targets.append(item.name)

        draw_header("Select MAPPING target")

        if existing_targets:
            choice = questionary.select(
                "Select an existing target or add a new one:",
                choices=existing_targets + ["➕ Add a target", "⬅ Back"],
                pointer="➤"
            ).ask()

            if choice == "⬅ Back":
                return

            if choice == "➕ Add a target":
                draw_header("Choosing MAPPING target")
                console.print("[bold white]Use:[/bold white] \n"
                              " [bold white]IP:[/bold white] [bold green]XX.XX.XX.XX[/bold green]\n"
                              " [bold white]IP Range:[/bold white] [bold green]XX.XX.XX.XX/CIDR[/bold green] or [bold green]XX.XX.XX.XX-XX[/bold green]\n"
                              " [bold white]Multiple IPs:[/bold white] [bold green]XX.XX.XX.XX,XX.XX.XX.XX[/bold green]\n"
                              " [bold white]Domain Name:[/bold white] [bold green]example.com[/bold green]")

                target = questionary.text("Enter target (IP, range, or domain):").ask()
                if not target:
                    return
            else:
                target_file = client_folder / choice / "target.txt"

                if target_file.exists():
                    target = target_file.read_text().strip()
                else:
                    target = choice

        else:
            draw_header("Choosing MAPPING target")
            console.print("[bold white]Use:[/bold white] \n"
                          " [bold white]IP:[/bold white] [bold green]XX.XX.XX.XX[/bold green]\n"
                          " [bold white]IP Range:[/bold white] [bold green]XX.XX.XX.XX/CIDR[/bold green] or [bold green]XX.XX.XX.XX-XX[/bold green]\n"
                          " [bold white]Multiple IPs:[/bold white] [bold green]XX.XX.XX.XX,XX.XX.XX.XX[/bold green]\n"
                          " [bold white]Domain Name:[/bold white] [bold green]example.com[/bold green]")

            target = questionary.text("Enter target (IP, range, or domain):").ask()
            if not target:
                return

        safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
        output_dir = client_folder / safe_target

        if output_dir.exists():
            shutil.rmtree(output_dir)

        output_dir.mkdir(parents=True, exist_ok=True)

        (output_dir / "target.txt").write_text(target)

        xml_file = output_dir / "nmap.xml"

        draw_header(f"MAPPING {target}")
        console.print("[*] Running mapping scan...")
        self.run_nmap_scan(target, xml_file)

        if not xml_file.exists():
            console.print("[red]Nmap scan failed. XML file not created.[/red]")
            return

        assets = self.parse_nmap(xml_file)

        traces = self.parse_traceroutes(xml_file)
        for a in assets:
            t = traces.get(a["ip"])
            if t:
                a["trace_hops"] = t["hops"]
                a["trace_path"] = t["path"]

        self.generate_outputs(assets, output_dir)
        self.generate_html_map(assets, output_dir)

        exposure = self.compute_exposure_by_zone(assets)
        criticality = self.compute_criticality_matrix(assets, exposure)
        global_score = self.compute_global_score(assets, criticality)

        self.generate_executive_report(
            assets,
            exposure,
            criticality,
            global_score,
            output_dir
        )

        self.generate_pdf_report(
            assets,
            exposure,
            criticality,
            global_score,
            output_dir
        )

        self.print_executive_summary(
            assets,
            exposure,
            criticality,
            global_score
        )

        console.print("[green][+] Mapping completed.[/green]")
        questionary.press_any_key_to_continue().ask()

    # ======================================================
    # EXPLORE RESULTS
    # ======================================================
    def explore_results(self):
        if not self.results_base.exists():
            console.print("[yellow]No results directory found.[/yellow]")
            questionary.press_any_key_to_continue().ask()
            return

        targets = sorted(os.listdir(self.results_base))

        if not targets:
            console.print("[yellow]No analyzed targets found.[/yellow]")
            questionary.press_any_key_to_continue().ask()
            return

        while True:
            draw_header("Select Mapping Target")

            choices = [f"🎯 {t}" for t in targets]
            choices.append("⬅ Back")

            selected = questionary.select(
                "Select a target:",
                choices=choices,
                pointer="➤"
            ).ask()

            if selected is None or selected == "⬅ Back":
                return

            selected_clean = selected.split(" ", 1)[1]
            target_path = self.results_base / selected_clean

            self.navigate_directory(target_path)

    def navigate_directory(self, path):
        while True:
            draw_header(f"Browsing: {path}")

            items = sorted(
                os.listdir(path),
                key=lambda x: (
                    not (path / x).is_dir(),
                    x.endswith(".txt"),
                    x.lower()
                )
            )

            if not items:
                console.print("[yellow]Empty directory.[/yellow]")
                questionary.press_any_key_to_continue().ask()
                return

            choices = []

            for item in items:
                full_path = path / item

                if full_path.is_dir():
                    icon = "📁"
                else:
                    ext = full_path.suffix.lower()

                    if ext == ".json":
                        icon = "📄"
                    elif ext == ".pdf":
                        icon = "📑"
                    elif ext == ".txt":
                        icon = "🧾"
                    else:
                        icon = "📦"

                label = f"{icon} {item}"
                choices.append(label)

            choices.append("⬅ Back")

            selected = questionary.select(
                "Select:",
                choices=choices,
                pointer="➤"
            ).ask()

            if selected is None or selected == "⬅ Back":
                return

            selected_clean = selected.split(" ", 1)[1]
            selected_path = path / selected_clean

            if selected_path.is_dir():
                self.navigate_directory(selected_path)

            else:
                console.print(f"\n[bold red]Opening {selected_clean}...[/bold red]")
                self.open_file(selected_path)

    # ======================================================
    # PDF TOOLS (merge mapping into recon pdf)
    # ======================================================
    def _safe_name(self, s: str) -> str:
        return re.sub(r"[^a-zA-Z0-9._-]", "_", s or "")

    def _list_mapping_runs(self):
        runs = []
        if not self.results_base.exists():
            return runs

        for client_dir in sorted([p for p in self.results_base.iterdir() if p.is_dir()], key=lambda p: p.name.lower()):
            for target_dir in sorted([p for p in client_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower()):
                mapping_pdf = target_dir / "executive_report.pdf"
                if mapping_pdf.exists():
                    runs.append({
                        "client": client_dir.name,
                        "target": target_dir.name,
                        "path": target_dir
                    })
        return runs

    def _find_recon_pdf_candidates(self, client_name: str, target_name: str):
        project_results = Path("results")
        candidates = {
            "match": None,
            "all_pdfs": []
        }

        client_dir = project_results / client_name
        if client_dir.exists() and client_dir.is_dir():
            direct = client_dir / target_name / "report.pdf"
            if direct.exists():
                candidates["match"] = direct

            for pdf in client_dir.rglob("*.pdf"):
                candidates["all_pdfs"].append(pdf)

        return candidates

    def _find_insert_index_before_author(self, recon_reader: PdfReader) -> int:
        needles = [
            "Author",
            "Analysis report prepared by",
        ]

        for i, page in enumerate(recon_reader.pages):
            try:
                txt = page.extract_text() or ""
            except Exception:
                txt = ""

            low = txt.lower()
            for n in needles:
                if n.lower() in low:
                    return i

        return len(recon_reader.pages)
    
    def _create_footer_overlay(self, page_number: int):
        packet = BytesIO()
        c = rl_canvas.Canvas(packet, pagesize=A4)

        width, height = A4

        if page_number > 1:
            logo_path, sign_path, name = _load_personalization()

            footer_y = 1.2 * cm
            line_y = 1.8 * cm

            c.setFillColor(colors.white)
            c.rect(
                0,
                0,
                width,
                2.5 * cm,
                fill=1,
                stroke=0
            )

            c.setStrokeColor(colors.lightgrey)
            c.setLineWidth(0.5)
            c.line(2*cm, line_y, width - 2*cm, line_y)

            if name:
                c.setFont("Helvetica", 8)
                c.setFillColor(colors.grey)
                c.drawString(2*cm, footer_y, name)

            if logo_path:
                try:
                    logo_w = 0.9 * cm
                    logo_h = 0.9 * cm
                    c.drawImage(
                        logo_path,
                        (width/2) - (logo_w/2),
                        footer_y - 0.5*cm,
                        width=logo_w,
                        height=logo_h,
                        preserveAspectRatio=True,
                        mask='auto'
                    )
                except:
                    pass

            c.setFont("Helvetica", 8)
            c.setFillColor(colors.grey)
            c.drawRightString(width - 2*cm, footer_y, f"Page {page_number}")

        c.showPage()
        c.save()
        packet.seek(0)

        return PdfReader(packet)

    def _merge_mapping_into_recon_pdf(self, recon_pdf: Path, mapping_pdf: Path):
        if not recon_pdf.exists():
            raise FileNotFoundError(f"Recon PDF not found: {recon_pdf}")
        if not mapping_pdf.exists():
            raise FileNotFoundError(f"Mapping PDF not found: {mapping_pdf}")

        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = recon_pdf.with_suffix(f".backup_{ts}.pdf")
        shutil.copy2(recon_pdf, backup_path)

        recon_reader = PdfReader(str(recon_pdf))
        mapping_reader = PdfReader(str(mapping_pdf))

        insert_at = self._find_insert_index_before_author(recon_reader)

        final_pages = []

        for i in range(0, insert_at):
            final_pages.append(recon_reader.pages[i])

        for page in mapping_reader.pages:
            final_pages.append(page)

        for i in range(insert_at, len(recon_reader.pages)):
            final_pages.append(recon_reader.pages[i])

        writer = PdfWriter()

        page_counter = 1

        for page in final_pages:
            overlay_pdf = self._create_footer_overlay(page_counter)
            overlay_page = overlay_pdf.pages[0]

            page.merge_page(overlay_page)

            writer.add_page(page)
            page_counter += 1

        with open(recon_pdf, "wb") as f:
            writer.write(f)

        return backup_path

    def add_cartography_to_recon(self):
        runs = self._list_mapping_runs()
        if not runs:
            draw_header("Add Cartography to a Recon")
            console.print("[yellow]No mapping cartography found yet.[/yellow]")
            questionary.press_any_key_to_continue().ask()
            return

        draw_header("Add Cartography to a Recon")
        choices = []
        for r in runs:
            choices.append(f"{r['client']}  |  {r['target']}")

        selected = safe_ask(
            questionary.select(
                "Select a cartography (mapping) to attach:",
                choices=choices + ["⬅ Back"],
                pointer="➤"
            )
        )

        if selected == "⬅ Back":
            return

        idx = choices.index(selected)
        run = runs[idx]

        client_name = run["client"]
        target_name = run["target"]
        mapping_dir = run["path"]
        mapping_pdf = mapping_dir / "executive_report.pdf"

        cands = self._find_recon_pdf_candidates(client_name, target_name)
        match = cands["match"]
        all_pdfs = cands["all_pdfs"]

        recon_pdf = None

        if match:
            draw_header("Recon PDF Found")
            use_match = questionary.confirm(
                f"Found matching Recon PDF:\n{match}\n\nDo you want to attach the cartography to this PDF?",
                default=True
            ).ask()

            if use_match:
                recon_pdf = match

        if recon_pdf is None:
            draw_header("Select Recon PDF")
            if not all_pdfs:
                console.print(f"[red]No PDF found in results/{client_name}[/red]")
                questionary.press_any_key_to_continue().ask()
                return

            display = []
            base = Path("results")
            for p in all_pdfs:
                try:
                    display.append(str(p.relative_to(base)))
                except Exception:
                    display.append(str(p))

            pick = questionary.select(
                "Select a Recon PDF to attach cartography to:",
                choices=display + ["⬅ Back"],
                pointer="➤"
            ).ask()

            if pick == "⬅ Back":
                return

            recon_pdf = base / pick if (base / pick).exists() else Path(pick)

        draw_header("Merging PDFs")
        console.print("[*] Recon PDF:", recon_pdf)
        console.print("[*] Mapping PDF:", mapping_pdf)

        try:
            backup = self._merge_mapping_into_recon_pdf(recon_pdf, mapping_pdf)
            console.print(f"[green][+] Cartography added successfully![/green]")
            console.print(f"[green][+] Backup created: {backup}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Failed to merge PDFs: {e}[/red]")

        questionary.press_any_key_to_continue().ask()

    # ======================================================
    # MAIN RUN
    # ======================================================
    def run(self, context=None):
        try: 
            while True:
                draw_header("Plugin: MAPPING")

                choice = questionary.select(
                    "Mapping Plugin:",
                    choices=[
                        "Run Mapping",
                        "Explore Results",
                        "Add Cartography to a Recon",
                        "⬅ Back"
                    ],
                    pointer="➤"
                ).ask()

                if choice == "Run Mapping":
                    self.run_mapping()

                elif choice == "Explore Results":
                    self.explore_results()

                elif choice == "Add Cartography to a Recon":
                    self.add_cartography_to_recon()

                else:
                    return
        except KeyboardInterrupt:
            return
