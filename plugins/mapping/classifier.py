from ipaddress import ip_address, ip_network

PRIVATE_RANGES = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]

# Icons used in the Scanopy-like rich CLI output
HOST_ICONS = {
    "Domain Controller":       "🏛️ ",
    "Linux Server":            "🐧 ",
    "Web Server":              "🌐 ",
    "Windows Server":          "🖥️ ",
    "Windows":                 "🖥️ ",
    "Router / Gateway":        "🔌 ",
    "Printer / Printing Server": "🖨️ ",
    "Database Server":         "🗄️ ",
    "Workstation / Unknown":   "❓ ",
}

RISK_COLORS = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "bold cyan",
    "low":      "bold green",
}


def classify_host(services, ip=None, default_gw=None):
    ports = [int(s["port"]) for s in services]
    if default_gw and ip == default_gw:
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


def detect_zone(ip, private_ranges=None):
    if private_ranges is None:
        private_ranges = PRIVATE_RANGES
    ip_obj = ip_address(ip)
    for network in private_ranges:
        if ip_obj in network:
            return "LAN"
    return "DMZ / External"


def compute_host_risk_score(services, zone, classification):
    score = 0
    risky_ports = [22, 3389, 445, 21, 25]
    for s in services:
        try:
            if int(s["port"]) in risky_ports:
                score += 2
        except (ValueError, KeyError):
            pass
    if zone == "DMZ / External":
        score += 3
    if classification == "Domain Controller":
        score += 5
    return min(score, 10)


def get_risk_style(score: int) -> str:
    """Return a Rich markup style string for a 0-10 risk score."""
    if score >= 7:
        return "bold red"
    if score >= 4:
        return "bold yellow"
    return "bold green"
