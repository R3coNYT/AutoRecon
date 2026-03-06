import ssl
import socket
from datetime import datetime

def tls_audit(host: str, port: int = 443):
    ctx = ssl.create_default_context()
    # we’re auditing, not bypassing; keep default validation
    info = {}
    try:
        with socket.create_connection((host, port), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info["protocol"] = ssock.version()
                info["cipher"] = ssock.cipher()

                # parse dates if present
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                info["cert_subject"] = cert.get("subject")
                info["cert_issuer"] = cert.get("issuer")
                info["not_before"] = not_before
                info["not_after"] = not_after

                # basic “health” flags
                if not_after:
                    # Example format: 'Jun  1 12:00:00 2026 GMT'
                    try:
                        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        info["cert_expired"] = dt < datetime.utcnow()
                    except Exception:
                        info["cert_expired"] = None
    except Exception as e:
        info["error"] = str(e)
    return info
