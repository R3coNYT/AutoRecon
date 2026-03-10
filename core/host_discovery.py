import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


def nmap_discover(target):
    try:
        result = subprocess.run(
            [
                "nmap",
                "-sn",
                "-n",
                "-PE",
                "-PP",
                "-PM",
                "-PS80,443",
                "-PA80,443",
                target
            ],
            capture_output=True,
            text=True
        )

        alive = []

        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                ip = line.split()[-1]
                alive.append(ip)

        return alive

    except Exception:
        return []


def discover_hosts(ips, threads=10):
    targets = []
    
    for ip in ips:

        if "/" in ip:
            targets.append(ip)

        else:
            try:
                ipaddress.ip_address(ip)
                targets.append(ip)
            except:
                continue

    alive = []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(nmap_discover, target): target for target in targets}
        
        for fut in as_completed(futures):

            try:
                res = fut.result()
                alive.extend(res)

            except:
                pass

    alive = list(set(alive))

    def ip_sort(ip):
        return tuple(map(int, ip.split(".")))

    return sorted(alive, key=ip_sort)
