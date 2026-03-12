import subprocess
import json


def run_nuclei(targets, severity="low,medium,high,critical"):
    if isinstance(targets, list):
        targets = "\n".join(targets)

    cmd = [
        "nuclei",
        "-json",
        "-silent",
        "-severity", severity
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
        print(f"[nuclei_error] {e}")
        return []

    vulns = []

    for line in stdout.splitlines():
        try:
            vulns.append(json.loads(line))
        except:
            pass

    return vulns