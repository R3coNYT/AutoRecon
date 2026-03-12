import subprocess
import json
import os
import shutil

HTTPX_BIN = shutil.which("httpx") or "httpx"

def run_httpx(targets, output_dir=None, target_name=None, timeout=10):

    if isinstance(targets, list):
        targets = "\n".join(targets)

    cmd = [
        HTTPX_BIN,
        "-silent",
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-timeout", str(timeout)
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        stdout, _ = process.communicate(targets)

    except Exception as e:
        print(f"[httpx_error] {e}")
        return []

    results = []

    for line in stdout.splitlines():
        try:
            results.append(json.loads(line))
        except:
            pass

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

        if target_name:
            file = f"httpx_{target_name}.json"
        else:
            file = "httpx.json"

        with open(os.path.join(output_dir, file), "w") as f:
            json.dump(results, f, indent=2)

    return results