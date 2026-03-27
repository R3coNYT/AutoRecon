"""Web service screenshots using gowitness."""

import subprocess
import shutil
import logging
from pathlib import Path

log = logging.getLogger("recon-audit")


def run_screenshots(urls: list, output_dir: Path, timeout: int = 20) -> list:
    """
    Capture screenshots for a list of URLs using gowitness.
    Returns list of {url, screenshot_path} dicts.
    """
    gowitness = shutil.which("gowitness")
    if not gowitness:
        log.info("gowitness not found — screenshots skipped")
        return []
    if not urls:
        return []

    screenshots_dir = output_dir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    url_file = output_dir / "screenshot_targets.txt"
    with open(url_file, "w") as f:
        f.write("\n".join(urls))

    cmd = [
        gowitness, "file",
        "-f", str(url_file),
        "--screenshot-path", str(screenshots_dir),
        "--timeout", str(timeout),
        "--disable-db",
    ]

    try:
        subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout * max(len(urls), 1) + 30,
        )
    except subprocess.TimeoutExpired:
        log.warning("gowitness timed out")
    except Exception as e:
        log.warning("gowitness error: %s", e)

    all_pngs = sorted(screenshots_dir.glob("*.png"))
    return [{"screenshot_path": str(p), "url": ""} for p in all_pngs]
