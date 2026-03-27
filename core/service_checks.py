"""
Service-specific security checks based on open ports.
- Port 21  → FTP anonymous login
- Port 22  → SSH banner / weak version
- Port 25/587 → SMTP open relay
- Port 445 → SMB note
- Port 6379 → Redis unauthenticated
- Port 27017 → MongoDB unauthenticated
"""

import socket
import logging
import re

log = logging.getLogger("recon-audit")
TIMEOUT = 8


def _banner(host: str, port: int, send: bytes = None) -> str:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            if send:
                s.sendall(send)
            return s.recv(2048).decode("utf-8", errors="replace")
    except Exception:
        return ""


def check_ftp_anon(host: str) -> dict:
    banner = _banner(host, 21)
    if not banner:
        return {"checked": False}
    try:
        with socket.create_connection((host, 21), timeout=TIMEOUT) as s:
            s.recv(2048)
            s.sendall(b"USER anonymous\r\n")
            s.recv(1024)
            s.sendall(b"PASS anonymous@\r\n")
            r2 = s.recv(1024).decode("utf-8", errors="replace")
            vulnerable = r2.startswith("230")
            return {
                "checked": True,
                "anonymous_login": vulnerable,
                "banner": banner[:200],
                "warning": "FTP anonymous login allowed" if vulnerable else None,
            }
    except Exception as e:
        return {"checked": True, "anonymous_login": False, "banner": banner[:200], "error": str(e)}


def check_ssh_banner(host: str, port: int = 22) -> dict:
    banner = _banner(host, port)
    if not banner:
        return {"checked": False}
    weak = []
    bl = banner.lower()
    if "ssh-1" in bl:
        weak.append("SSHv1 detected (deprecated, exploitable)")
    m = re.search(r"openssh[_\-](\d+)\.(\d+)", bl)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        if major < 7:
            weak.append(f"OpenSSH {major}.{minor} — very old version, likely vulnerable")
    return {
        "checked": True,
        "banner": banner.strip()[:200],
        "weak_indicators": weak,
        "warning": weak[0] if weak else None,
    }


def check_smtp_relay(host: str, port: int = 25) -> dict:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            banner = s.recv(2048).decode("utf-8", errors="replace")
            s.sendall(b"EHLO recon-probe.local\r\n")
            s.recv(2048)
            s.sendall(b"MAIL FROM:<probe@recon-probe.local>\r\n")
            s.recv(1024)
            s.sendall(b"RCPT TO:<probe@gmail.com>\r\n")
            to_resp = s.recv(1024).decode("utf-8", errors="replace")
            s.sendall(b"QUIT\r\n")
            relay = to_resp.startswith("250") or to_resp.startswith("251")
            return {
                "checked": True,
                "banner": banner.strip()[:200],
                "open_relay": relay,
                "rcpt_response": to_resp.strip()[:100],
                "warning": "SMTP open relay detected — spam / phishing abuse possible" if relay else None,
            }
    except Exception as e:
        return {"checked": True, "error": str(e)}


def check_redis_noauth(host: str, port: int = 6379) -> dict:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            s.sendall(b"PING\r\n")
            resp = s.recv(128).decode("utf-8", errors="replace")
            if "+PONG" in resp:
                return {
                    "checked": True,
                    "unauthenticated": True,
                    "warning": "Redis accessible without authentication — data exposure / RCE via SLAVEOF possible",
                }
            elif "NOAUTH" in resp or "WRONGPASS" in resp:
                return {"checked": True, "unauthenticated": False}
            return {"checked": True, "unauthenticated": False, "response": resp[:50]}
    except Exception as e:
        return {"checked": True, "error": str(e)}


def check_mongodb_noauth(host: str, port: int = 27017) -> dict:
    # Minimal OP_QUERY isMaster
    msg = (
        b"\x3f\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\xd4\x07\x00\x00"
        b"\x00\x00\x00\x00"
        b"admin.$cmd\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x13\x00\x00\x00"
        b"\x10ismaster\x00\x01\x00\x00\x00\x00"
    )
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            s.sendall(msg)
            resp = s.recv(2048)
            if resp and b"ismaster" in resp.lower():
                return {
                    "checked": True,
                    "unauthenticated": True,
                    "warning": "MongoDB accessible without authentication — data exposure possible",
                }
            return {"checked": True, "unauthenticated": False}
    except Exception as e:
        return {"checked": True, "error": str(e)}


def check_smb_open(host: str) -> dict:
    banner = _banner(host, 445)
    return {
        "checked": bool(banner),
        "banner": banner[:100] if banner else "",
        "note": "SMB port 445 open — verify null sessions, signing, EternalBlue" if banner else "",
    }


def run_service_checks(host: str, open_ports: list) -> dict:
    """Run all applicable service checks based on detected open ports."""
    port_nums = set()
    for p in open_ports:
        try:
            port_nums.add(int(p.get("port", 0)))
        except (TypeError, ValueError):
            pass

    results = {}

    if 21 in port_nums:
        log.info("Service check: FTP anon on %s:21", host)
        results["ftp"] = check_ftp_anon(host)

    if 22 in port_nums:
        log.info("Service check: SSH banner on %s:22", host)
        results["ssh"] = check_ssh_banner(host, 22)

    if 25 in port_nums or 587 in port_nums:
        port = 25 if 25 in port_nums else 587
        log.info("Service check: SMTP relay on %s:%d", host, port)
        results["smtp"] = check_smtp_relay(host, port)

    if 445 in port_nums:
        log.info("Service check: SMB on %s:445", host)
        results["smb"] = check_smb_open(host)

    if 6379 in port_nums:
        log.info("Service check: Redis noauth on %s:6379", host)
        results["redis"] = check_redis_noauth(host)

    if 27017 in port_nums:
        log.info("Service check: MongoDB noauth on %s:27017", host)
        results["mongodb"] = check_mongodb_noauth(host)

    return results
