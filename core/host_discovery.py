import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

def ping_host(ip, timeout=1):
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0
    except:
        return False


def discover_hosts(ips, threads=50):
    alive = []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in ips}

        for fut in as_completed(futures):
            ip = futures[fut]

            try:
                if fut.result():
                    alive.append(ip)
            except:
                pass

    return sorted(alive, key=lambda x: tuple(map(int, x.split("."))))