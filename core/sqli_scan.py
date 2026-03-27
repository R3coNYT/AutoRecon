"""
SQL injection scanner using SQLmap.

Strategy
--------
For each crawled page that has query parameters or HTML forms, run sqlmap in
batch / non-interactive mode and collect its findings from the JSON output.

SQLmap is invoked as a subprocess with safe, non-destructive flags:
  --batch           — never prompt, use defaults
  --level 2         — moderate crawl depth inside sqlmap
  --risk  1         — only safe tests (no heavy UPDATEs / time-based by default)
  --output-dir      — write results to the audit output directory
  --forms           — also test HTML forms on the page
  --json-output     — machine-readable JSON summary

If sqlmap is not installed / not in PATH the scanner gracefully returns [].

Tested pages are deduplicated — each unique (url, param combination) is only
submitted once.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs

log = logging.getLogger("recon-audit")

# Resolve the AutoRecon project root (core/../)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# SQLmap binary — searches PATH first, then the bundled sqlmap-dev clone, then common locations.
_SQLMAP_CANDIDATES = [
    "sqlmap",
    "sqlmap.py",
    str(_PROJECT_ROOT / "sqlmap-dev" / "sqlmap.py"),
    "C:/Tools/sqlmap/sqlmap.py",
    "/usr/bin/sqlmap",
    "/usr/local/bin/sqlmap",
    "/opt/sqlmap/sqlmap.py",
]


def _find_sqlmap() -> str | None:
    """Return the first usable sqlmap command or None."""
    if found := shutil.which("sqlmap"):
        return found
    for candidate in _SQLMAP_CANDIDATES:
        if shutil.which(candidate):
            return candidate
        p = Path(candidate)
        if p.exists():
            return str(p)
    return None


def _has_injectable_surface(url: str) -> bool:
    """Return True when the URL has query-string parameters worth testing."""
    qs = urlparse(url).query
    return bool(parse_qs(qs))


def _run_sqlmap(
    url: str,
    output_dir: Path,
    timeout: int,
    extra_args: list[str] | None = None,
) -> list[dict]:
    """
    Run sqlmap against a single URL and return a list of finding dicts.

    Each finding has:
        type, url, parameter, db_type, technique, evidence
    """
    sqlmap_bin = _find_sqlmap()
    if sqlmap_bin is None:
        log.debug("sqlmap not found — skipping SQL injection scan")
        return []

    # Per-URL output sub-directory so sqlmap logs don't collide
    safe_url = re.sub(r"[^\w]", "_", url)[:80]
    url_out_dir = output_dir / safe_url
    url_out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sqlmap_bin,
        "-u", url,
        "--batch",           # never ask user input
        "--level", "2",      # test headers + cookies as well
        "--risk", "1",       # only safe payloads
        "--forms",           # also try HTML forms on the page
        "--output-dir", str(url_out_dir),
        "--timeout", str(timeout),
        "--retries", "1",
        "--threads", "3",
        "--smart",           # skip targets that clearly don't have injection points
        "--no-cast",         # faster, less noise
        "--technique", "BEUS",  # Boolean, Error, Union, Stacked — skip time-based (T)
    ]

    if extra_args:
        cmd.extend(extra_args)

    log.info("SQLmap scanning: %s", url)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(120, timeout * 10),  # sqlmap needs more time than a single request
        )
    except subprocess.TimeoutExpired:
        log.warning("SQLmap timed out for %s", url)
        return []
    except Exception as exc:
        log.warning("SQLmap execution failed for %s: %s", url, exc)
        return []

    # Parse sqlmap stdout for injection confirmations
    findings: list[dict] = []
    output = proc.stdout + proc.stderr

    # Pattern: "Parameter: X (GET/POST)" followed by "Type: ..." / "Title: ..."
    # SQLmap log format example:
    #   Parameter: id (GET)
    #       Type: boolean-based blind
    #       Title: AND boolean-based blind - WHERE or HAVING clause
    param_blocks = re.findall(
        r"Parameter: (\S+) \((GET|POST|Cookie|User-Agent|.*?)\)(.*?)(?=Parameter:|$)",
        output,
        re.DOTALL | re.IGNORECASE,
    )

    for param, method, block in param_blocks:
        techs = re.findall(r"Type:\s*(.+)", block)
        titles = re.findall(r"Title:\s*(.+)", block)
        if techs:
            findings.append({
                "type":      "sqli",
                "url":       url,
                "method":    method.strip().upper(),
                "parameter": param.strip(),
                "technique": ", ".join(t.strip() for t in techs),
                "evidence":  titles[0].strip() if titles else "SQL injection confirmed by sqlmap",
            })

    # Also check if sqlmap found a back-end DBMS
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", output, re.IGNORECASE)
    db_type = dbms_match.group(1).strip() if dbms_match else None
    for f in findings:
        f["db_type"] = db_type

    # Persist raw sqlmap output alongside other results
    raw_log_path = url_out_dir / "sqlmap_output.txt"
    try:
        raw_log_path.write_text(output, encoding="utf-8", errors="replace")
    except Exception:
        pass

    if findings:
        log.info("SQLmap found %d injection(s) on %s", len(findings), url)

    return findings


def scan_sqli(
    pages: list[dict],
    output_dir: Path,
    timeout: int = 7,
) -> list[dict]:
    """
    Run SQLmap against all crawled pages that have injectable surfaces.

    Args:
        pages:      List of page dicts from crawl_site() — each has {"url": ...}.
        output_dir: Base directory to store sqlmap output files.
        timeout:    Per-request timeout hint (sqlmap uses a larger internal timeout).

    Returns:
        List of finding dicts with keys:
            type, url, method, parameter, technique, db_type, evidence
    """
    sqlmap_bin = _find_sqlmap()
    if sqlmap_bin is None:
        log.info("sqlmap not found in PATH — SQL injection scan skipped. "
                 "Install sqlmap (pip install sqlmap  or  apt install sqlmap) to enable.")
        return []

    sqli_out = output_dir / "sqlmap"
    sqli_out.mkdir(parents=True, exist_ok=True)

    # Deduplicate URLs — one sqlmap run per URL (--forms covers in-page forms too)
    seen_urls: set[str] = set()
    findings: list[dict] = []

    for page in pages:
        url = page.get("url", "")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)

        # Only run sqlmap when there is something to inject into
        # (sqlmap's --forms flag handles pages without query params too,
        #  but we still skip obvious binary/media endpoints)
        parsed = urlparse(url)
        ext = Path(parsed.path).suffix.lower()
        if ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                   ".css", ".js", ".woff", ".woff2", ".ttf", ".pdf"):
            continue

        findings.extend(_run_sqlmap(url, sqli_out, timeout))

    return findings
