import subprocess
import shutil
import logging
import re
import json
from pathlib import Path

log = logging.getLogger("recon-audit")


def _wordlist_path() -> str | None:
    project_root = Path(__file__).resolve().parents[1]
    wl = project_root / "wordlists" / "File_Dir.txt"
    return str(wl) if wl.exists() else None


def run_dir_bruteforce(url: str, output_dir: Path = None, timeout: int = 120) -> list:
    """Brute-force directories/files with gobuster or ffuf. Returns list of findings."""
    wordlist = _wordlist_path()
    if not wordlist:
        log.warning("Wordlist not found — skipping dir bruteforce")
        return []

    gobuster = shutil.which("gobuster")
    ffuf = shutil.which("ffuf")

    if gobuster:
        return _run_gobuster(gobuster, url, wordlist, output_dir, timeout)
    elif ffuf:
        return _run_ffuf(ffuf, url, wordlist, output_dir, timeout)
    else:
        log.info("Neither gobuster nor ffuf found — skipping dir bruteforce")
        return []


def _run_gobuster(binary, url, wordlist, output_dir, timeout):
    cmd = [
        binary, "dir",
        "-u", url,
        "-w", wordlist,
        "-q",
        "--no-tls-validation",
        "-t", "20",
        "--timeout", "10s",
    ]
    output_file = None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        safe = url.replace("://", "_").replace("/", "_").replace(":", "_")
        output_file = output_dir / f"gobuster_{safe[:60]}.txt"
        cmd += ["-o", str(output_file)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return _parse_gobuster(proc.stdout)
    except subprocess.TimeoutExpired:
        log.warning("gobuster timed out on %s", url)
        return []
    except Exception as e:
        log.debug("gobuster error: %s", e)
        return []


def _parse_gobuster(output: str) -> list:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)(?:.*\[Size:\s*(\d+)\])?", line)
        if m:
            findings.append({
                "path": m.group(1),
                "status": int(m.group(2)),
                "size": int(m.group(3)) if m.group(3) else None,
            })
    return findings


def _run_ffuf(binary, url, wordlist, output_dir, timeout):
    target_url = url.rstrip("/") + "/FUZZ"
    cmd = [
        binary,
        "-u", target_url,
        "-w", wordlist,
        "-mc", "200,204,301,302,307,401,403",
        "-of", "json",
        "-s",
        "-t", "20",
    ]
    output_file = None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        safe = url.replace("://", "_").replace("/", "_").replace(":", "_")
        output_file = output_dir / f"ffuf_{safe[:60]}.json"
        cmd += ["-o", str(output_file)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if output_file and output_file.exists():
            with open(output_file) as f:
                data = json.load(f)
            return [
                {"path": r.get("url", ""), "status": r.get("status"), "size": r.get("length")}
                for r in data.get("results", [])
            ]
        return _parse_ffuf_stdout(proc.stdout)
    except subprocess.TimeoutExpired:
        log.warning("ffuf timed out on %s", url)
        return []
    except Exception as e:
        log.debug("ffuf error: %s", e)
        return []


def _parse_ffuf_stdout(output: str) -> list:
    findings = []
    for line in output.splitlines():
        try:
            r = json.loads(line)
            findings.append({"path": r.get("url", ""), "status": r.get("status"), "size": r.get("length")})
        except Exception:
            pass
    return findings
