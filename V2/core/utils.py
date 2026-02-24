import socket
import ipaddress


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def reverse_dns_lookup(ip: str):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return None
