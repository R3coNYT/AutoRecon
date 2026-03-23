import sys
from pathlib import Path

_PLUGIN_DIR = Path(__file__).parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

import xml.etree.ElementTree as ET
from classifier import classify_host, detect_zone, compute_host_risk_score, PRIVATE_RANGES


def parse_nmap_xml(xml_file, default_gw=None, private_ranges=None):
    """Parse a Nmap XML output file and return a list of asset dicts."""
    if private_ranges is None:
        private_ranges = PRIVATE_RANGES

    tree = ET.parse(xml_file)
    root = tree.getroot()
    assets = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = host.find("address").get("addr")

        services = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                services.append({"port": port.get("portid")})

        classification = classify_host(services, ip=ip, default_gw=default_gw)
        zone = detect_zone(ip, private_ranges)
        risk_score = compute_host_risk_score(services, zone, classification)

        assets.append({
            "ip":             ip,
            "zone":           zone,
            "classification": classification,
            "risk_score":     risk_score,
            "services":       services,
        })

    return assets


def parse_traceroutes(xml_file):
    """Extract per-host traceroute hop data from a Nmap XML file."""
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
            ttl    = hop.get("ttl")
            rtt    = hop.get("rtt")

            if not hop_ip:
                continue

            try:
                ttl_i = int(ttl) if ttl else None
            except Exception:
                ttl_i = None

            try:
                rtt_f = float(rtt) if rtt else None
            except Exception:
                rtt_f = None

            hops.append({"ttl": ttl_i, "ip": hop_ip, "rtt": rtt_f})
            hop_ips.append(hop_ip)

        if hops:
            path = hop_ips[:] + [dest_ip]
            traces[dest_ip] = {"hops": hops, "hop_ips": hop_ips, "path": path}

    return traces
