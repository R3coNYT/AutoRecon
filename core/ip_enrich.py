import ipaddress
import socket
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
