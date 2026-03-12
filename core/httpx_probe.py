import subprocess
import json


def run_httpx(targets, timeout=10):
    if isinstance(targets, list):
        targets = "\n".join(targets)

    cmd = [
        "httpx",
        "-silent",
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-ports",
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

    return results