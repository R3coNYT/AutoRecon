import os
import sys
import subprocess
import logging
from typing import List

log = logging.getLogger("recon-audit")

def _write_fallback(out_file: str, target: str):
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(target.strip() + "\n")

def run_sublist3r(target: str, out_dir: str) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "subdomains.txt")

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sublist3r_py = os.path.join(project_root, "Sublist3r", "sublist3r.py")

    if not os.path.exists(sublist3r_py):
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

    if not os.path.exists(out_file):
        log.warning("Sublist3r did not create output. Using fallback list.")
        _write_fallback(out_file, target)

    subs = []
    with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
        subs = [line.strip() for line in f if line.strip()]

    if target not in subs:
        subs.insert(0, target)

    return sorted(set(subs))