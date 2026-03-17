import ipaddress
import socket
import struct
import requests

def resolve_domain_to_ips(domain: str):
    ips = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            ip = sockaddr[0]
            # filtre IP valides
            ipaddress.ip_address(ip)
            ips.add(ip)
    except Exception:
        pass
    return sorted(ips)

def reverse_dns(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ── NetBIOS Node Status (UDP 137) ──────────────────────────────────────────────

def _netbios_encode_name(raw: bytes) -> bytes:
    """Encode a 16-byte NetBIOS name using nibble encoding (RFC 1002)."""
    out = bytearray()
    for b in raw[:16]:
        out.append(0x41 + (b >> 4))
        out.append(0x41 + (b & 0x0F))
    return bytes(out)


def netbios_hostname(ip: str, timeout: float = 2.0):
    """
    Send a NetBIOS Node Status Request (UDP 137) to retrieve the machine's
    computer name. Very effective on Windows LAN hosts that have no DNS record
    (DHCP-only machines, workstations with split-zone DNS, etc.).
    Returns the NetBIOS workstation name or None.
    """
    # Wildcard name: '*' (0x2A) + 15 null bytes → encodes to CKAAAAA…
    name_raw = b'\x2A' + b'\x00' * 15
    encoded  = _netbios_encode_name(name_raw)

    packet = (
        b'\x00\x01'      # Transaction ID
        b'\x00\x00'      # Flags: standard query
        b'\x00\x01'      # QDCOUNT: 1
        b'\x00\x00'      # ANCOUNT: 0
        b'\x00\x00'      # NSCOUNT: 0
        b'\x00\x00'      # ARCOUNT: 0
        + b'\x20'        # Name length: 32
        + encoded        # 32-byte encoded name
        + b'\x00'        # End of name
        + b'\x00\x21'    # QTYPE: NBSTAT (33)
        + b'\x00\x01'    # QCLASS: IN  (1)
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
    except Exception:
        return None

    # Response layout:
    #   Header:   12 bytes
    #   Question: 34 bytes (name) + 4 bytes (type+class) = 38 bytes  → total 50
    #   Answer name: 2-byte compression pointer OR 34-byte copy
    #   Then: type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes
    #   RDATA: num_names(1) + 18 bytes per name entry
    try:
        if len(data) <= 50:
            return None

        rr_name_len = 2 if (data[50] & 0xC0 == 0xC0) else 34
        rdata_start = 50 + rr_name_len + 10   # skip answer-name + type/class/ttl/rdlen

        if rdata_start >= len(data):
            return None

        num_names = data[rdata_start]
        offset = rdata_start + 1

        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name  = data[offset:offset + 15]
            name_type = data[offset + 15]
            flags     = struct.unpack_from('>H', data, offset + 16)[0]
            offset   += 18

            # type 0x00, unique (GROUP bit 0x8000 not set) → workstation name
            if name_type == 0x00 and not (flags & 0x8000):
                # Keep only printable ASCII bytes (0x20–0x7E) — drops nulls,
                # control chars (\x1c, \x04, …) and any other garbage bytes.
                name = bytes(b for b in raw_name if 0x20 <= b <= 0x7E)
                name = name.decode('ascii', errors='ignore').strip()
                return name if name else None
    except Exception:
        return None

    return None


# ── mDNS reverse PTR (UDP 5353) ────────────────────────────────────────────────

def _encode_dns_name(name: str) -> bytes:
    encoded = b''
    for part in name.rstrip('.').split('.'):
        encoded += bytes([len(part)]) + part.encode('ascii')
    return encoded + b'\x00'


def _decode_dns_name(data: bytes, offset: int):
    """Decode a DNS wire-format name, following compression pointers.
    Returns (name_str, new_offset)."""
    parts = []
    visited = set()
    end_offset = offset
    jumped = False

    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)

        length = data[offset]

        if length == 0:
            if not jumped:
                end_offset = offset + 1
            break

        if (length & 0xC0) == 0xC0:
            if not jumped:
                end_offset = offset + 2
            jumped = True
            pointer = struct.unpack_from('>H', data, offset)[0] & 0x3FFF
            offset = pointer
            continue

        offset += 1
        if offset + length > len(data):
            break
        parts.append(data[offset:offset + length].decode('ascii', errors='ignore'))
        offset += length

    return '.'.join(parts), end_offset


def mdns_hostname(ip: str, timeout: float = 2.0):
    """
    Send a unicast mDNS PTR query (UDP 5353) directly to the host.
    Works on Windows 10+, Linux, and macOS hosts with mDNS support.
    Returns the short hostname (without .local suffix) or None.
    """
    parts = ip.split('.')
    query_name = '.'.join(reversed(parts)) + '.in-addr.arpa'

    packet  = struct.pack('>HHHHHH', 0x0001, 0x0000, 1, 0, 0, 0)
    packet += _encode_dns_name(query_name)
    packet += struct.pack('>HH', 12, 1)   # QTYPE=PTR, QCLASS=IN

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 5353))
        data, _ = sock.recvfrom(4096)
        sock.close()
    except Exception:
        return None

    try:
        flags    = struct.unpack_from('>H', data, 2)[0]
        an_count = struct.unpack_from('>H', data, 6)[0]
        if not (flags & 0x8000) or an_count == 0:
            return None

        offset  = 12
        qdcount = struct.unpack_from('>H', data, 4)[0]
        for _ in range(qdcount):
            _, offset = _decode_dns_name(data, offset)
            offset += 4   # QTYPE + QCLASS

        for _ in range(an_count):
            _, offset = _decode_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack_from('>HHIH', data, offset)
            offset += 10
            if rtype == 12:   # PTR record
                ptr_name, _ = _decode_dns_name(data, offset)
                hostname = ptr_name.rstrip('.')
                # Keep the full FQDN (e.g. livebox.home) — only strip .local
                if hostname.endswith('.local'):
                    hostname = hostname[:-6]
                return hostname if hostname else None
            offset += rdlen
    except Exception:
        pass

    return None


# ── Direct DNS PTR query to a specific nameserver ─────────────────────────────

def _guess_gateway(ip: str):
    """Derive the likely local gateway (x.x.x.1) from any LAN IP."""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return None


def _dns_ptr_query(ip: str, nameserver: str, timeout: float = 2.0):
    """
    Send a raw UDP DNS PTR query directly to *nameserver* (port 53).
    Bypasses the system resolver — useful when the local router serves a
    private zone (.home, .lan, .local) that upstream DNS doesn't forward.
    Returns the FQDN answer or None.
    """
    parts = ip.split('.')
    query_name = '.'.join(reversed(parts)) + '.in-addr.arpa'

    packet  = struct.pack('>HHHHHH', 0xAB01, 0x0100, 1, 0, 0, 0)
    packet += _encode_dns_name(query_name)
    packet += struct.pack('>HH', 12, 1)   # QTYPE=PTR, QCLASS=IN

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
    except Exception:
        return None

    try:
        flags    = struct.unpack_from('>H', data, 2)[0]
        an_count = struct.unpack_from('>H', data, 6)[0]
        if not (flags & 0x8000) or an_count == 0:
            return None

        offset  = 12
        qdcount = struct.unpack_from('>H', data, 4)[0]
        for _ in range(qdcount):
            _, offset = _decode_dns_name(data, offset)
            offset += 4

        for _ in range(an_count):
            _, offset = _decode_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack_from('>HHIH', data, offset)
            offset += 10
            if rtype == 12:   # PTR
                ptr_name, _ = _decode_dns_name(data, offset)
                return ptr_name.rstrip('.') or None
            offset += rdlen
    except Exception:
        pass

    return None


# ── Combined hostname resolver ─────────────────────────────────────────────────

def resolve_hostname(ip: str):
    """
    Resolve a hostname for the given IP using four methods:

      1. Reverse DNS (system resolver) — standard PTR lookup.
      2. Direct PTR query to the local gateway (x.x.x.1, port 53) —
         handles .home / .lan zones served by the local router/DHCP server
         when the system resolver doesn't forward them, OR when the system
         resolver returned only a bare name (no domain, e.g. via LLMNR).
      3. NetBIOS Node Status (UDP 137) — Windows DHCP-only machines.
      4. mDNS PTR (UDP 5353) — Windows 10+, Linux, macOS.
    """
    host = reverse_dns(ip)

    # Prefer a FQDN from the gateway's DNS over a bare name from LLMNR/NetBIOS.
    # Also covers the case where the system resolver returns nothing at all.
    if not host or '.' not in host:
        gateway = _guess_gateway(ip)
        if gateway:
            gw_host = _dns_ptr_query(ip, gateway)
            if gw_host:
                host = gw_host

    if host:
        return host

    host = netbios_hostname(ip)
    if host:
        return host

    host = mdns_hostname(ip)
    if host:
        return host

    return None


def rdap_ip_lookup(ip: str, timeout: int = 10):
    """
    RDAP: standard moderne (remplace WHOIS brut).
    Renvoie infos réseau + org quand dispo.
    """
    url = f"https://rdap.org/ip/{ip}"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "ReconAudit/1.0"})
        if r.status_code != 200:
            return {"error": f"RDAP HTTP {r.status_code}"}
        data = r.json()

        # champs variables selon registres (RIPE/ARIN/APNIC/...)
        out = {
            "handle": data.get("handle"),
            "name": data.get("name"),
            "type": data.get("type"),
            "startAddress": data.get("startAddress"),
            "endAddress": data.get("endAddress"),
            "country": data.get("country"),
            "parentHandle": data.get("parentHandle"),
            "rdap_url": url,
        }

        # Tentative d'extraction d'org/ASN-like depuis entities (souvent présent)
        entities = data.get("entities", [])
        out["entities"] = entities[:10]  # on limite

        return out
    except Exception as e:
        return {"error": str(e)}

def geo_ip_api(ip: str, timeout: int = 10):
    """
    Exemple simple. Tu peux remplacer par ipinfo ou MaxMind.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "ReconAudit/1.0"})
        data = r.json()
        if data.get("status") != "success":
            return {"error": data.get("message", "geo lookup failed")}
        return {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),  # contient souvent ASN string
        }
    except Exception as e:
        return {"error": str(e)}
