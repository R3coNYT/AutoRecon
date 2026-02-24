import os
import subprocess
from typing import List

def run_sublist3r(target: str, out_dir: str) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "subdomains.txt")

    cmd = ["python3", "Sublist3r/sublist3r.py", "-d", target, "-o", out_file]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    subs = []
    if os.path.exists(out_file):
        with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
            subs = [line.strip() for line in f if line.strip()]

    # fallback: include root target
    if target not in subs:
        subs.insert(0, target)

    # dedup
    return sorted(set(subs))
