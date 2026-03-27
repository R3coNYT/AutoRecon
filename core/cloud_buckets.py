"""
Cloud bucket detection — discovers exposed S3, GCS, Azure Blob, and other
cloud storage buckets related to a target domain.

Strategy:
  1. Generate candidate bucket names from the target domain/subdomain.
  2. Try to resolve / HTTP-probe each candidate across all major cloud providers.
  3. Check if the bucket is publicly listable (unauthenticated LIST).
  4. Also scan crawled pages / JS sources for hardcoded bucket URLs.
"""
import re
import logging
import ipaddress
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse

log = logging.getLogger("recon-audit")

# Cloud storage endpoint patterns
_PROVIDERS = {
    "s3":          "https://{bucket}.s3.amazonaws.com/",
    "s3-us-east":  "https://{bucket}.s3.us-east-1.amazonaws.com/",
    "gcs":         "https://storage.googleapis.com/{bucket}/",
    "azure":       "https://{bucket}.blob.core.windows.net/",
    "digitalocean":"https://{bucket}.nyc3.digitaloceanspaces.com/",
    "backblaze":   "https://{bucket}.s3.us-west-002.backblazeb2.com/",
}

# Regex to find bucket URLs already referenced in page content
_BUCKET_URL_RE = re.compile(
    r"https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\."
    r"(s3\.amazonaws\.com|s3\.[a-z0-9\-]+\.amazonaws\.com"
    r"|storage\.googleapis\.com"
    r"|blob\.core\.windows\.net"
    r"|[a-z0-9]+\.digitaloceanspaces\.com"
    r"|s3\.[a-z0-9\-]+\.backblazeb2\.com)",
    re.IGNORECASE,
)

_OPEN_INDICATORS = [
    b"<ListBucketResult",   # S3 / GCS public list
    b"<?xml",               # generic XML listing
    b"BucketName",
    b"Contents",
    b"<EnumerationResults", # Azure
    b"<Blobs>",
]

_DENIED_INDICATORS = [
    b"AccessDenied",
    b"AuthorizationRequired",
    b"Forbidden",
    b"NoSuchBucket",
    b"The specified container does not exist",
]


def _is_ip(target: str) -> bool:
    """Return True if target looks like an IP address (v4 or v6)."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _candidate_names(domain: str) -> list[str]:
    """Generate bucket name candidates from a domain or subdomain."""
    base = domain.split(".")[0].lower()
    # strip common TLDs
    parts = domain.lower().replace("-", "").split(".")
    names = set()
    names.add(base)
    if len(parts) >= 2:
        names.add(parts[0])
        names.add(f"{parts[0]}-{parts[1]}")
        names.add(f"{parts[0]}.{parts[1]}")
    suffixes = ["", "-backup", "-backups", "-data", "-assets", "-files",
                "-static", "-media", "-dev", "-prod", "-staging", "-logs",
                "-uploads", "-public", "-private", "-storage", "-archive"]
    expanded = set()
    for n in list(names):
        for s in suffixes:
            candidate = (n + s).strip("-.")
            if 3 <= len(candidate) <= 63:
                expanded.add(candidate)
    return list(expanded)


def _probe_bucket(url: str, timeout: int = 6) -> dict | None:
    """
    Try fetching a bucket URL.
    Returns a dict if the bucket exists (open or closed), None if non-existent.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AutoRecon/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096)
            status = resp.status
            is_open = any(ind in body for ind in _OPEN_INDICATORS)
            return {"url": url, "status": status, "public": is_open, "body_snippet": body[:200].decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        if e.code in (403, 400):
            # Bucket exists but access denied
            return {"url": url, "status": e.code, "public": False, "body_snippet": ""}
        if e.code == 404:
            return None  # does not exist
        return None
    except Exception:
        return None


def _scan_pages_for_buckets(pages: list[dict]) -> list[str]:
    """Extract bucket URLs referenced in crawled page content."""
    found = set()
    for page in pages:
        content = page.get("html", "") or ""
        for m in _BUCKET_URL_RE.finditer(content):
            found.add(m.group(0).split("?")[0].rstrip("/") + "/")
    return list(found)


def run_cloud_bucket_detection(target: str, pages: list[dict] | None = None,
                                timeout: int = 6) -> list[dict]:
    """
    Main entry point.

    Returns list of findings:
    [
      {
        "url": "https://company-backup.s3.amazonaws.com/",
        "provider": "s3",
        "bucket_name": "company-backup",
        "public": True/False,
        "status": 200,
        "source": "enumeration" | "page_reference",
        "severity": "HIGH" | "MEDIUM" | "INFO",
      }
    ]
    """
    findings = []
    checked = set()

    # ── 1. Enumerate candidates — only for domain targets, not IPs ─────────
    if not _is_ip(target):
        candidates = _candidate_names(target)
        for bucket_name in candidates:
            for provider, url_tpl in _PROVIDERS.items():
                url = url_tpl.format(bucket=bucket_name)
                if url in checked:
                    continue
                checked.add(url)
                result = _probe_bucket(url, timeout)
                if result:
                    severity = "HIGH" if result["public"] else "MEDIUM"
                    findings.append({
                        "url": url,
                        "provider": provider,
                        "bucket_name": bucket_name,
                        "public": result["public"],
                        "status": result["status"],
                        "source": "enumeration",
                        "severity": severity,
                    })
                    log.info("Cloud bucket found: %s (public=%s)", url, result["public"])

    # ── 2. Scan page content ─────────────────────────────────────────────────
    if pages:
        for bucket_url in _scan_pages_for_buckets(pages):
            if bucket_url in checked:
                continue
            checked.add(bucket_url)
            result = _probe_bucket(bucket_url, timeout)
            parsed = urlparse(bucket_url)
            bucket_name = parsed.netloc.split(".")[0]
            if result:
                severity = "HIGH" if result["public"] else "MEDIUM"
            else:
                severity = "INFO"
            findings.append({
                "url": bucket_url,
                "provider": "unknown",
                "bucket_name": bucket_name,
                "public": result["public"] if result else False,
                "status": result["status"] if result else 0,
                "source": "page_reference",
                "severity": severity,
            })
            log.info("Cloud bucket ref in pages: %s", bucket_url)

    return findings
