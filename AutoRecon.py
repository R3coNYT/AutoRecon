import os
import sys
import shutil
import re
import subprocess
import zipfile
import questionary
import logging
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from main import main as recon_main
from core.banner import print_banner
from core.plugin_loader import load_plugins
from core.result_browser import browse_results
from core.client_folder_select import select_or_create_client_folder

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

os.environ["PYTHONIOENCODING"] = "utf-8"

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
# CHECK DEPENDENCIES
# =========================
def check_dependencies():
    import shutil

    tools = ["nmap", "masscan", "httpx", "nuclei"]

    for t in tools:
        if shutil.which(t):
            print(f"[✓] {t} detected")
        else:
            print(f"[✗] {t} not found")

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
                "Config",
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

        elif choice == "Config":
            handle_config()

        elif choice == "Exit":
            console.print("\n[bold red]Exiting...[/bold red]")
            sys.exit()


# =========================
# RECON HANDLER
# =========================
def handle_recon():
    results_base = RESULTS_DIR
    client_folder = select_or_create_client_folder(results_base)
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

    # ── Backup previous scan results as a ZIP ─────────────────────────────
    if output_dir.exists():
        # Collect items to archive (everything except backup/)
        items_to_backup = [p for p in output_dir.iterdir() if p.name != "backup"]
        if items_to_backup:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            was_ai = (output_dir / "ai_scan").exists()
            prefix = "ai_" if was_ai else ""
            zip_name = f"{prefix}{safe_target}_{ts}.zip"
            backup_dir = output_dir / "backup"
            backup_dir.mkdir(parents=True, exist_ok=True)
            zip_path = backup_dir / zip_name
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for item in items_to_backup:
                    if item.is_dir():
                        for file in item.rglob("*"):
                            zf.write(file, file.relative_to(output_dir))
                    else:
                        zf.write(item, item.relative_to(output_dir))
            # Remove backed-up content (keep backup/ intact)
            for item in items_to_backup:
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
    else:
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
# CONFIG EDITOR
# =========================
def handle_config():
    # Locate .env — same logic as main.py
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        env_example = BASE_DIR / ".env.example"
        if env_example.exists():
            shutil.copy(env_example, env_file)
            console.print(f"[bold yellow].env created from .env.example[/bold yellow]")
        else:
            env_file.touch()
            console.print(f"[bold yellow].env created (empty)[/bold yellow]")

    console.print(f"\n[bold cyan]Editing:[/bold cyan] {env_file}")
    console.print("[dim]Save and close the editor to return to the menu.[/dim]\n")

    # Pick editor: honour $EDITOR, fall back to platform default
    editor = os.environ.get("EDITOR", "")
    if not editor:
        if sys.platform.startswith("win"):
            editor = "notepad"
        elif shutil.which("nano"):
            editor = "nano"
        elif shutil.which("vi"):
            editor = "vi"
        else:
            editor = "vi"

    try:
        subprocess.call([editor, str(env_file)])
    except FileNotFoundError:
        console.print(f"[bold red]Editor '{editor}' not found.[/bold red] Set the EDITOR env var.")
        questionary.press_any_key_to_continue().ask()
        return

    # Reload .env into os.environ so the new config takes effect immediately
    try:
        from dotenv import load_dotenv
        load_dotenv(env_file, override=True)
        console.print("\n[bold green].env reloaded successfully.[/bold green]")
    except ImportError:
        console.print("\n[bold yellow].env saved but python-dotenv not installed — restart to apply changes.[/bold yellow]")

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
    check_dependencies()
    main_menu()