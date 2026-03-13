import re
import questionary
from pathlib import Path
from rich.console import Console
from core.banner import print_banner

console = Console()


def draw_header(title="Results Browser"):
    console.clear()
    print_banner()
    console.rule("[bold red]AutoRecon Console[/bold red]")
    console.print(f"[bold red]{title}[/bold red]")


def select_or_create_client_folder(results_base: Path):

    results_base.mkdir(parents=True, exist_ok=True)

    while True:
        draw_header("Select Client Folder")

        folders = sorted(
            [f.name for f in results_base.iterdir()if f.is_dir()]
        )

        choice = questionary.select(
            "Select an existing folder or create a new one:",
            choices=folders + ["➕ Create a folder", "⬅ Back"],
            pointer="➤"
        ).ask()

        if choice == "⬅ Back":
            return None

        if choice == "➕ Create a folder":
            name = questionary.text("Enter new folder name:").ask()
            if not name:
                continue

            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
            new_path = results_base / safe_name

            if not new_path.exists():
                new_path.mkdir()
                console.print(f"[+] Folder created: {safe_name}")
            else:
                console.print("[yellow]Folder already exists.[/yellow]")

            continue

        return results_base / choice