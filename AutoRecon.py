import os
import sys
import shutil
import re
from io import StringIO
import questionary
import logging
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from main import main as recon_main
from core.banner import print_banner
from core.plugin_loader import load_plugins
from core.result_browser import browse_results
from core.client_folder_select import select_or_create_client_folder

log = logging.getLogger("recon-audit")
console = Console()

# =========================
# HEADER STYLE METASPLOIT
# =========================
def draw_header():
    console.clear()
    print_banner()
    console.rule("[bold red]AutoRecon Console[/bold red]")


# =========================
# LOADING ANIMATION
# =========================
def loading(message="Launching..."):
    with Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold white]{task.description}"),
        transient=True,
        console=console
    ) as progress:
        progress.add_task(description=message, total=None)
        import time
        time.sleep(1)


# =========================
# MAIN MENU
# =========================
def main_menu():
    while True:
        draw_header()

        choice = questionary.select(
            "Select an option:",
            choices=[
                "Recon on a target",
                "Recon Results",
                "Plugins",
                "Exit"
            ],
            pointer="➤"
        ).ask()

        if choice == "Recon on a target":
            handle_recon()

        elif choice == "Recon Results":
            browse_results()

        elif choice == "Plugins":
            handle_plugins()

        elif choice == "Exit":
            console.print("\n[bold red]Exiting...[/bold red]")
            sys.exit()


# =========================
# RECON HANDLER
# =========================
def handle_recon():
    client_folder = select_or_create_client_folder("opt/autorecon/results")
    if not client_folder:
        return

    existing_targets = []
    if client_folder.exists():
        for item in sorted(client_folder.iterdir(), key=lambda p: p.name.lower()):
            if item.is_dir():
                existing_targets.append(item.name)

    draw_header()

    target = None

    if existing_targets:
        choice = questionary.select(
            "Select an existing target or add a new one:",
            choices=existing_targets + ["➕ Add a target", "⬅ Back"],
            pointer="➤"
        ).ask()

        if choice == "⬅ Back" or not choice:
            return

        if choice == "➕ Add a target":
            draw_header()
            target = questionary.text("Enter target (IP / domain / CIDR network e.g. 192.168.1.0/24):").ask()
            if not target:
                return
        else:
            target_file = client_folder / choice / "target.txt"
            if target_file.exists():
                target = target_file.read_text(encoding="utf-8").strip()
            else:
                target = choice
    else:
        draw_header()
        target = questionary.text("Enter target (IP / domain / CIDR network e.g. 192.168.1.0/24):").ask()
        if not target:
            return
    
    safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    output_dir = client_folder / safe_target

    if output_dir.exists():
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True)

    try:
        (output_dir / "target.txt").write_text(target, encoding="utf-8")
    except Exception:
        pass

    full_scan = questionary.confirm(
        "Run FULL Nmap scan (all ports)?",
        default=False
    ).ask()

    args = [
        "-t", target,
        "--threads", "16",
        "--crawl-depth", "2",
        "--max-pages", "150",
        "--pdf",
        "--output-dir", str(output_dir)
    ]

    if full_scan:
        args.append("--full")

    console.print("\n[bold red]Launching scan...[/bold red]")

    loading("Initializing engine...")

    recon_main(args)

    console.print("\n[bold green]Scan completed.[/bold green]")
    questionary.press_any_key_to_continue().ask()


# =========================
# PLUGINS
# =========================
def handle_plugins():
    draw_header()

    plugins = load_plugins()

    if not plugins:
        console.print("[bold yellow]No plugins detected.[/bold yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    plugin_choices = [f"{p.name} - {p.description}" for p in plugins]

    selected = questionary.select(
        "Select a plugin:",
        choices=plugin_choices + ["⬅ Back"],
        pointer="➤"
    ).ask()

    if not selected or selected == "⬅ Back":
        return

    index = plugin_choices.index(selected)
    plugin = plugins[index]

    draw_header()
    console.print(f"[bold red]Launching plugin:[/bold red] [bold]{plugin.name}[/bold]\n")

    try:
        plugin.run(context={
            "console": console,
            "questionary": questionary,
            "logger": log,
            "draw_header": draw_header,
        })
    except TypeError:
        try:
            plugin.run()
        except TypeError:
            plugin.run("")

    console.print("\n[bold green]Plugin finished.[/bold green]")
    questionary.press_any_key_to_continue().ask()


if __name__ == "__main__":
    main_menu()