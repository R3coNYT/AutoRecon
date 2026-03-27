"""
JWT token analysis — finds JWT tokens in HTTP responses, cookies, and JS files,
then analyzes them for security weaknesses.

Checks performed:
  - Algorithm: none / HS256 with empty/weak secret (alg confusion)
  - Sensitive data in payload (email, password, role, admin, etc.)
  - Token expiry (exp claim)
  - Missing security claims (iss, aud, jti)
  - Unverified signature (no secret brute-force, just structural check)
"""
import base64
import json
import logging
import re
import time
import urllib.request

log = logging.getLogger("recon-audit")

# Regex to find JWTs anywhere in text
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"
)

_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "access_token", "refresh_token", "ssn", "credit_card",
    "card_number", "cvv", "pin",
}

_WEAK_SECRETS = [
    "", "secret", "password", "123456", "qwerty", "changeme",
    "supersecret", "mysecret", "jwt_secret", "your-secret",
]

_INTERESTING_CLAIMS = {"role", "admin", "is_admin", "group", "permissions",
                       "scope", "user_id", "email", "sub", "username"}


def _b64_decode(s: str) -> bytes:
    """Decode Base64URL without padding."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _decode_jwt(token: str) -> dict | None:
    """Decode header + payload without verifying signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return {"header": header, "payload": payload, "raw": token}
    except Exception:
        return None


def _check_none_alg(header: dict) -> bool:
    alg = header.get("alg", "")
    return str(alg).lower() in ("none", "", "null")


def _check_weak_hmac(token: str) -> str | None:
    """Try trivial secrets against HS256/HS384/HS512 token."""
    try:
        import hmac
        import hashlib
        parts = token.split(".")
        msg = (parts[0] + "." + parts[1]).encode()
        sig = _b64_decode(parts[2])
        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        header = json.loads(_b64_decode(parts[0]))
        alg = header.get("alg", "HS256")
        hash_fn = alg_map.get(alg.upper())
        if not hash_fn:
            return None
        for secret in _WEAK_SECRETS:
            expected = hmac.new(secret.encode(), msg, hash_fn).digest()
            if hmac.compare_digest(expected, sig):
                return secret if secret else "(empty string)"
    except Exception:
        pass
    return None


def _analyze_token(token: str, source: str) -> dict:
    decoded = _decode_jwt(token)
    if not decoded:
        return {"token": token[:40] + "...", "source": source, "error": "decode_failed"}

    header = decoded["header"]
    payload = decoded["payload"]
    issues = []
    severity = "INFO"

    # Algorithm check
    alg = header.get("alg", "unknown")
    if _check_none_alg(header):
        issues.append("Algorithm 'none' — signature not verified")
        severity = "HIGH"

    # Weak secret check (only for HMAC algorithms)
    if alg.upper().startswith("HS"):
        cracked = _check_weak_hmac(token)
        if cracked is not None:
            issues.append(f"Weak HMAC secret cracked: '{cracked}'")
            severity = "HIGH"

    # Expiry check
    exp = payload.get("exp")
    if exp:
        if exp < time.time():
            issues.append("Token is expired but may still be accepted")
            if severity == "INFO":
                severity = "LOW"
    else:
        issues.append("No 'exp' claim — token never expires")
        if severity == "INFO":
            severity = "MEDIUM"

    # Sensitive data in payload
    sens_found = []
    for key in payload:
        if key.lower() in _SENSITIVE_KEYS:
            sens_found.append(key)
    if sens_found:
        issues.append(f"Sensitive claims in payload: {sens_found}")
        if severity not in ("HIGH",):
            severity = "MEDIUM"

    # Interesting/privilege claims
    interesting = {k: payload[k] for k in payload if k.lower() in _INTERESTING_CLAIMS}

    return {
        "token": token[:60] + ("..." if len(token) > 60 else ""),
        "source": source,
        "algorithm": alg,
        "payload_claims": list(payload.keys()),
        "interesting_claims": interesting,
        "issues": issues,
        "severity": severity,
    }


def _extract_tokens_from_text(text: str, source: str) -> list[dict]:
    results = []
    seen = set()
    for match in _JWT_RE.finditer(text):
        token = match.group(0)
        if token in seen:
            continue
        seen.add(token)
        analysis = _analyze_token(token, source)
        if "error" not in analysis:
            results.append(analysis)
    return results


def _fetch_js(url: str, timeout: int = 8) -> str:
    """Fetch a JS file and return its content."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AutoRecon/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(512 * 1024).decode("utf-8", errors="replace")
    except Exception:
        return ""


def scan_jwt_tokens(pages: list[dict], headers: dict | None = None,
                    timeout: int = 8) -> list[dict]:
    """
    Main entry point. Scans:
      - HTTP response headers (Authorization, Set-Cookie)
      - Crawled page HTML content
      - JS files linked in pages

    Returns deduplicated list of JWT analysis dicts.
    """
    findings = []
    seen_tokens = set()

    def _add(analysis_list: list[dict]):
        for item in analysis_list:
            token_short = item.get("token", "")
            if token_short not in seen_tokens:
                seen_tokens.add(token_short)
                findings.append(item)

    # 1. Scan response headers
    if headers:
        for hdr_name, hdr_val in headers.items():
            text = str(hdr_val)
            _add(_extract_tokens_from_text(text, f"header:{hdr_name}"))

    # 2. Scan page HTML + cookies
    js_urls_found = set()
    for page in pages:
        html = page.get("html", "") or ""
        page_url = page.get("url", "page")
        _add(_extract_tokens_from_text(html, f"page:{page_url}"))

        # Collect JS URLs
        for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html, re.IGNORECASE):
            js_ref = m.group(1)
            if js_ref.startswith("http"):
                js_urls_found.add(js_ref)
            elif js_ref.startswith("/") and page_url.startswith("http"):
                from urllib.parse import urljoin
                js_urls_found.add(urljoin(page_url, js_ref))

        # Scan cookies stored in page data
        cookies_raw = page.get("cookies", "")
        if cookies_raw:
            _add(_extract_tokens_from_text(str(cookies_raw), f"cookie:{page_url}"))

    # 3. Scan JS files (limit to 20)
    for js_url in list(js_urls_found)[:20]:
        content = _fetch_js(js_url, timeout)
        if content:
            _add(_extract_tokens_from_text(content, f"js:{js_url}"))

    if findings:
        log.info("JWT analysis: %d token(s) found, %d with issues",
                 len(findings),
                 sum(1 for f in findings if f.get("issues")))

    return findings
