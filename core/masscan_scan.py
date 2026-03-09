import subprocess
import json

def run_masscan(target, rate=10000, ports="1-65535"):
    cmd = [
        "masscan",
        target,
        "-p", ports,
        "--rate", str(rate),
        "--wait", "2",
        "-oJ", "-"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        if not result.stdout.strip():
            return {}

        data = json.loads(result.stdout)

        results = {}

        for entry in data:
            ip = entry["ip"]
            port = entry["ports"][0]["port"]

            results.setdefault(ip, []).append(port)

        return results

    except Exception:
        return {}