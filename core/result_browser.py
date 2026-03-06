import os
import subprocess
import platform
import questionary
from rich.console import Console
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
    console.print(f"[bold red]{title}[/bold red]")


# =========================
# NAVIGATION RECURSIVE
# =========================
def navigate_directory(path):
    while True:
        draw_header(f"Browsing: {os.path.basename(path)}")

        items = os.listdir(path)

        if not items:
            console.print("[yellow]Empty directory.[/yellow]")
            questionary.press_any_key_to_continue().ask()
            return

        choices = []

        # Ajouter dossiers + fichiers
        for item in items:
            full_path = os.path.join(path, item)

            if os.path.isdir(full_path):
                choices.append(f"[DIR] {item}")
            else:
                choices.append(item)

        choices.append("⬅ Back")

        selected = questionary.select(
            "Select:",
            choices=choices,
            pointer="➤"
        ).ask()

        if selected == "⬅ Back":
            return

        selected_clean = selected.replace("[DIR] ", "")
        selected_path = os.path.join(path, selected_clean)

        if os.path.isdir(selected_path):
            navigate_directory(selected_path)
        else:
            console.print(f"[bold red]Opening {selected_clean}...[/bold red]")
            open_file(selected_path)


# =========================
# MAIN BROWSER ENTRY
# =========================
def browse_results():
    if not os.path.exists(RESULTS_DIR):
        console.print("[yellow]No results directory found.[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    targets = os.listdir(RESULTS_DIR)

    if not targets:
        console.print("[yellow]No analyzed targets found.[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    while True:
        draw_header("Select Target")

        choices = targets + ["⬅ Back"]

        selected = questionary.select(
            "Select a target:",
            choices=choices,
            pointer="➤"
        ).ask()

        if selected == "⬅ Back":
            return

        target_path = os.path.join(RESULTS_DIR, selected)
        navigate_directory(target_path)