import sys
import subprocess
import logging
from typing import List
from pathlib import Path

log = logging.getLogger("recon-audit")

def _write_fallback(out_file: Path, target: str):
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(target.strip() + "\n")

def run_sublist3r(target: str, out_dir: Path) -> List[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "subdomains.txt"
    project_root = Path(__file__).resolve().parent.parent
    sublist3r_project_root = project_root / "Sublist3r"
    sublist3r_py = sublist3r_project_root / "sublist3r.py"

    if not sublist3r_py.exists():
        log.error("Sublist3r script not found: %s", sublist3r_py)
        _write_fallback(out_file, target)
        return [target]

    cmd = [sys.executable, sublist3r_py, "-d", target, "-o", out_file]

    proc = subprocess.run(
        cmd,
        cwd=project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if not out_file.exists():
        log.warning("Sublist3r did not create output. Using fallback list.")
        _write_fallback(out_file, target)

    subs = []
    with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
        subs = [line.strip() for line in f if line.strip()]

    if target not in subs:
        subs.insert(0, target)

    return sorted(set(subs))