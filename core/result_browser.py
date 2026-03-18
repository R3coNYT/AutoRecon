import subprocess
import platform
import questionary
from pathlib import Path
from rich.console import Console
from core.banner import print_banner

console = Console()

# =========================
# PATHS CROSS OS
# =========================
BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"


# =========================
# OUVERTURE FICHIER
# =========================

# Extensions that can be displayed as text directly in the terminal
_TEXT_EXTS = {'.txt', '.json', '.xml', '.nmap', '.gnmap', '.log', '.md', '.csv', '.html'}

def open_file(path):
    path_obj = Path(path)
    ext = path_obj.suffix.lower()

    # Text files: display content inline — works in any terminal (including headless PTY)
    if ext in _TEXT_EXTS:
        try:
            content = path_obj.read_text(encoding='utf-8', errors='replace')
            console.print(f"\n[bold cyan]── {path_obj.name} ──[/bold cyan]\n")
            console.print(content)
        except Exception as exc:
            console.print(f"[red]Cannot read file: {exc}[/red]")
        input("\nPress Enter to continue…")
        return

    # Binary / GUI files: try OS association, fall back gracefully if no desktop is available
    try:
        if platform.system() == "Windows":
            import os
            os.startfile(str(path))
        elif platform.system() == "Darwin":
            subprocess.run(["open", str(path)])
        else:
            subprocess.run(["xdg-open", str(path)])
    except OSError:
        console.print(f"\n[yellow]Cannot open [bold]{path_obj.name}[/bold] in a terminal session.[/yellow]")
        console.print(f"[dim]File path: {path}[/dim]")
        input("\nPress Enter to continue…")


# =========================
# HEADER
# =========================
def draw_header(title="Results Browser"):

    console.clear()
    print_banner()
    console.rule("[bold red]AutoRecon Console[/bold red]")
    console.print(f"[bold red]{title}[/bold red]\n")


# =========================
# ICONES
# =========================
def get_icon(name, is_dir):

    if is_dir:
        return "📁"

    ext = Path(name).suffix.lower()

    if ext == ".json":
        return "📄"
    elif ext == ".pdf":
        return "📑"
    elif ext == ".txt":
        return "🧾"
    else:
        return "📦"


# =========================
# FILE SORTING
# =========================
def sort_items(path):

    items = list(path.iterdir())

    return sorted(
        items,
        key=lambda x: (
            not x.is_dir(),
            x.name.endswith(".txt"),
            x.name.endswith(".xml"),
            x.name.endswith(".json"),
            x.name.lower()
        )
    )


# =========================
# NAVIGATION
# =========================
def navigate_directory(path):

    while True:

        draw_header(f"Browsing: {path.relative_to(BASE_DIR)}")

        items = sort_items(path)

        if not items:

            console.print("[yellow]Empty directory.[/yellow]")
            questionary.press_any_key_to_continue().ask()
            return

        choices = []

        for item in items:

            icon = get_icon(item.name, item.is_dir())
            label = f"{icon} {item.name}"

            choices.append(label)

        choices.append("⬅ Back")

        selected = questionary.select(
            "Select:",
            choices=choices,
            pointer="➤"
        ).ask()

        if selected is None or selected == "⬅ Back":
            return

        selected_clean = selected.split(" ", 1)[1]
        selected_path = path / selected_clean

        if selected_path.is_dir():

            navigate_directory(selected_path)

        else:

            console.print(f"\n[bold red]Opening {selected_clean}...[/bold red]")
            open_file(selected_path)


# =========================
# BROWSER ENTRY
# =========================
def browse_results():

    if not RESULTS_DIR.exists():

        console.print("[yellow]No results directory found.[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    targets = sorted([p.name for p in RESULTS_DIR.iterdir() if p.is_dir()])

    if not targets:

        console.print("[yellow]No analyzed targets found.[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    while True:

        draw_header("Select Target")

        choices = [f"🎯 {t}" for t in targets]
        choices.append("⬅ Back")

        selected = questionary.select(
            "Select a target:",
            choices=choices,
            pointer="➤"
        ).ask()

        if selected is None or selected == "⬅ Back":
            return

        selected_clean = selected.split(" ", 1)[1]
        target_path = RESULTS_DIR / selected_clean

        navigate_directory(target_path)