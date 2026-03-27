"""
Parameter discovery via arjun.
Discovers hidden/undocumented GET & POST parameters on web endpoints.
Falls back gracefully if arjun is not installed.
"""
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger("recon-audit")


def _arjun_available() -> bool:
    return shutil.which("arjun") is not None


def run_param_discovery(urls: list[str], output_dir: Path | None = None,
                        timeout: int = 120) -> list[dict]:
    """
    Run arjun against each URL.

    Returns list of findings:
    [
      {
        "url": "http://example.com/api/user",
        "method": "GET",
        "parameters": ["id", "token", "debug"],
      }
    ]
    """
    if not _arjun_available():
        log.debug("arjun not found — skipping parameter discovery")
        return []

    if not urls:
        return []

    findings = []

    with tempfile.TemporaryDirectory() as tmp:
        for url in urls:
            safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")[:80]
            out_file = Path(tmp) / f"arjun_{safe_name}.json"

            cmd = [
                "arjun",
                "-u", url,
                "--stable",
                "-oJ", str(out_file),
                "-t", "5",           # threads
                "-d", "2",           # delay between requests (seconds)
                "-q",                # quiet
            ]

            try:
                subprocess.run(
                    cmd,
                    timeout=timeout,
                    capture_output=True,
                    text=True,
                )
            except subprocess.TimeoutExpired:
                log.warning("arjun timed out on %s", url)
                continue
            except Exception as e:
                log.warning("arjun error on %s: %s", url, e)
                continue

            if out_file.exists():
                try:
                    data = json.loads(out_file.read_text(encoding="utf-8"))
                    # arjun output format: list of {url, params} or {url: {GET: [], POST: []}}
                    if isinstance(data, list):
                        for entry in data:
                            params = entry.get("params") or []
                            if params:
                                findings.append({
                                    "url": entry.get("url", url),
                                    "method": entry.get("method", "GET"),
                                    "parameters": params,
                                })
                    elif isinstance(data, dict):
                        for method in ("GET", "POST"):
                            params = data.get(method, [])
                            if params:
                                findings.append({
                                    "url": url,
                                    "method": method,
                                    "parameters": params,
                                })
                    if findings:
                        log.info("arjun found params on %s: %s",
                                 url, [f.get("parameters") for f in findings if f.get("url") == url])
                except Exception as e:
                    log.warning("arjun output parse error for %s: %s", url, e)

    return findings
