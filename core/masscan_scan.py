import subprocess
import json
import shutil
import os
import signal

MASSCAN_BIN = shutil.which("masscan") or "C:/Tools/bin/masscan.exe"

MASSCAN_TIMEOUT = int(os.environ.get("MASSCAN_TIMEOUT", 800))

def _kill_process(proc):
    try:
        if os.name == "nt":
            subprocess.call(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

def run_masscan(target: str, rate=2000, ports="1-65535", timeout=None):
    if timeout is None:
        timeout = MASSCAN_TIMEOUT

    cmd = [
        MASSCAN_BIN,
        target,
        "-p", ports,
        "--rate", str(rate),
        "--wait", "2",
        "-oJ", "-"
    ]

    output = ""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            **({"start_new_session": True} if os.name != "nt" else {}),
        )

        effective_timeout = timeout if timeout > 0 else None
        try:
            stdout, _ = proc.communicate(timeout=effective_timeout)
            output = stdout.decode(errors="replace")
        except subprocess.TimeoutExpired:
            print(
                f"[masscan_timeout] Masscan scan exceeded {timeout}s on {target}, "
                "it was automatically interrupted."
            )
            _kill_process(proc)
            proc.communicate()
            return {}

    except FileNotFoundError:
        print(f"[masscan_error] Bin not found : {MASSCAN_BIN}")
        return {}
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