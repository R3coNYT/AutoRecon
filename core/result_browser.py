import os
import subprocess
import platform
import questionary
from rich.console import Console
from rich.text import Text
from core.banner import print_banner

console = Console()
RESULTS_DIR = "results"


# =========================
# OUVERTURE FICHIER
# =========================
def open_file(path):
    if platform.system() == "Windows":
        os.startfile(path)
    elif platform.system() == "Darwin":
        subprocess.run(["open", path])
    else:
        subprocess.run(["xdg-open", path])


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

    ext = os.path.splitext(name)[1].lower()

    if ext == ".json":
        return "📄"
    elif ext == ".pdf":
        return "📑"
    elif ext == ".txt":
        return "🧾"
    else:
        return "📦"


# =========================
# TRI FICHIERS
# =========================
def sort_items(path):

    items = os.listdir(path)

    return sorted(
        items,
        key=lambda x: (
            not os.path.isdir(os.path.join(path, x)),  # dossiers en premier
            x.endswith(".txt"),                        # txt en dernier
            x.lower()
        )
    )


# =========================
# NAVIGATION
# =========================
def navigate_directory(path):

    while True:

        draw_header(f"Browsing: {path}")

        items = sort_items(path)

        if not items:
            console.print("[yellow]Empty directory.[/yellow]")
            questionary.press_any_key_to_continue().ask()
            return

        choices = []

        for item in items:

            full_path = os.path.join(path, item)
            icon = get_icon(item, os.path.isdir(full_path))

            label = f"{icon} {item}"
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
        selected_path = os.path.join(path, selected_clean)

        if os.path.isdir(selected_path):
            navigate_directory(selected_path)

        else:
            console.print(f"\n[bold red]Opening {selected_clean}...[/bold red]")
            open_file(selected_path)


# =========================
# BROWSER ENTRY
# =========================
def browse_results():

    if not os.path.exists(RESULTS_DIR):

        console.print("[yellow]No results directory found.[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    targets = sorted(os.listdir(RESULTS_DIR))

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
        target_path = os.path.join(RESULTS_DIR, selected_clean)

        navigate_directory(target_path)