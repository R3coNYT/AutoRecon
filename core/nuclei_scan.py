import subprocess
import json
import os


def run_nuclei(targets, output_dir=None, severity="low,medium,high,critical"):

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

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

        with open(os.path.join(output_dir, "nuclei.json"), "w") as f:
            json.dump(vulns, f, indent=2)

    return vulns