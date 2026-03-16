import xml.etree.ElementTree as ET


def _clean(val):
    """Return None when nmap emits an empty string or '?' for unknown fields."""
    if val is None:
        return None
    val = val.strip()
    return None if not val or not val.replace("?", "").strip() else val


def parse_nmap_xml(xml_path):

    tree = ET.parse(xml_path)
    root = tree.getroot()

    result = {
        "ip": None,
        "hostname": None,
        "open_ports": []
    }

    host = root.find("host")

    if host is None:
        return result

    address = host.find("address")
    if address is not None:
        result["ip"] = address.get("addr")

    hostname = host.find(".//hostname")
    if hostname is not None:
        result["hostname"] = hostname.get("name")

    ports = host.find("ports")

    if ports is None:
        return result

    for port in ports.findall("port"):

        state = port.find("state")

        if state is None or state.get("state") != "open":
            continue

        service = port.find("service")

        result["open_ports"].append({
            "port": int(port.get("portid")),
            "proto": port.get("protocol"),
            "service": service.get("name") if service is not None else None,
            "product": _clean(service.get("product")) if service is not None else None,
            "version": _clean(service.get("version")) if service is not None else None
        })

    return result