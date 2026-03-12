import subprocess
import json


def run_masscan(target: str, rate=2000, ports="1-65535"):
    cmd = [
        "masscan",
        target,
        "-p", ports,
        "--rate", str(rate),
        "--wait", "2",
        "-oJ", "-"
    ]

    try:
        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        output = result.decode()

    except Exception as e:
        print(f"[masscan_error] {e}")
        return {}

    hosts = {}

    try:
        data = json.loads(output)

        for entry in data:
            ip = entry["ip"]
            port = entry["ports"][0]["port"]

            hosts.setdefault(ip, []).append(port)

    except Exception:
        return {}

    return hosts