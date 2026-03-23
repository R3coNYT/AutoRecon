import subprocess
import re
import shutil
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

NMAP_BIN = shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"


def detect_default_gateway() -> str | None:
    """Detect the default gateway on Linux/macOS via `ip route`."""
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True).strip()
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def discover_alive_hosts(target: str) -> list[str]:
    """
    Run an Nmap ping-sweep and return a list of alive IP addresses.
    Displays a Scanopy-like rich table of discovered hosts.
    """
    console.print(
        Panel(
            f"[bold white]Target:[/bold white] [cyan]{target}[/cyan]\n"
            "[dim]Running ping sweep (ICMP + TCP SYN 80/443)…[/dim]",
            title="[bold blue]🔍  Host Discovery[/bold blue]",
            border_style="blue",
            expand=False,
        )
    )

    try:
        result = subprocess.run(
            [
                NMAP_BIN,
                "-sn", "-n",
                "-PE", "-PP", "-PM",
                "-PS80,443",
                "-PA80,443",
                target,
            ],
            capture_output=True,
            text=True,
        )
    except Exception as e:
        console.print(f"[red][!] Host discovery failed: {e}[/red]")
        return []

    alive = []
    for line in result.stdout.splitlines():
        if "Nmap scan report for" in line:
            ip = line.split()[-1].strip("()")
            alive.append(ip)

    # ── Scanopy-like rich table ──────────────────────────────────────────────
    if alive:
        tbl = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan", expand=False)
        tbl.add_column("IP Address", style="bold white", no_wrap=True, min_width=18)
        tbl.add_column("Status",     justify="center",  min_width=10)
        for ip in alive:
            tbl.add_row(ip, "[bold green]● alive[/bold green]")
        console.print(
            Panel(
                tbl,
                title=f"[bold cyan]🖧  {len(alive)} host(s) discovered[/bold cyan]",
                border_style="cyan",
                expand=False,
            )
        )
    else:
        console.print("[yellow][!] No alive hosts found.[/yellow]")

    return alive


def run_nmap_scan(target: str, output_xml: Path) -> None:
    """
    Run a full Nmap service/OS/traceroute scan against the alive hosts
    found in *target* and save results to *output_xml*.
    """
    alive_hosts = discover_alive_hosts(target)

    if not alive_hosts:
        console.print("[red][!] No alive hosts — scan aborted.[/red]")
        return

    cleaned = [h.strip("()") for h in alive_hosts]

    console.print(
        Panel(
            f"[dim]Scanning {len(cleaned)} host(s) — service detection, OS fingerprinting, traceroute…[/dim]",
            title="[bold magenta]⚡  Nmap Deep Scan[/bold magenta]",
            border_style="magenta",
            expand=False,
        )
    )

    subprocess.run(
        [
            NMAP_BIN,
            "-sS", "-sV", "-O",
            "--traceroute",
            "-T4", "-Pn",
            "-oX", str(output_xml),
            *cleaned,
        ]
    )
