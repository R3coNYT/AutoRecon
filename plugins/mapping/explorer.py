import sys
from pathlib import Path

_PLUGIN_DIR = Path(__file__).parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

import questionary
from ui import draw_header, safe_ask, open_file_cross_platform, console


def navigate_directory(path: Path) -> None:
    """Interactive directory browser for a single mapping result folder."""
    path = Path(path)

    while True:
        draw_header(f"Browsing: {path}")

        items = sorted(
            [p.name for p in path.iterdir()],
            key=lambda x: (not (path / x).is_dir(), x.endswith(".txt"), x.lower()),
        )

        if not items:
            console.print("[yellow]Empty directory.[/yellow]")
            questionary.press_any_key_to_continue().ask()
            return

        choices = []
        for item in items:
            full_path = path / item
            if full_path.is_dir():
                icon = "📁"
            else:
                ext = full_path.suffix.lower()
                if ext == ".json":
                    icon = "📄"
                elif ext == ".pdf":
                    icon = "📑"
                elif ext == ".txt":
                    icon = "🧾"
                else:
                    icon = "📦"
            choices.append(f"{icon} {item}")

        choices.append("⬅ Back")

        selected = questionary.select("Select:", choices=choices, pointer="➤").ask()

        if selected is None or selected == "⬅ Back":
            return

        selected_clean = selected.split(" ", 1)[1]
        selected_path  = path / selected_clean

        if selected_path.is_dir():
            navigate_directory(selected_path)
        else:
            console.print(f"\n[bold red]Opening {selected_clean}…[/bold red]")
            open_file_cross_platform(selected_path)


def explore_results(results_base: Path) -> None:
    """Top-level results browser — lets the user pick a client then a target."""
    if not results_base.exists():
        console.print("[yellow]No results directory found.[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    # Two-level hierarchy: results_base / client / target
    clients = sorted([p for p in results_base.iterdir() if p.is_dir()], key=lambda p: p.name.lower())

    if not clients:
        console.print("[yellow]No results found.[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    while True:
        draw_header("Explore Mapping Results")

        client_choices = [f"📂 {c.name}" for c in clients] + ["⬅ Back"]
        sel_client = questionary.select("Select a client:", choices=client_choices, pointer="➤").ask()

        if sel_client is None or sel_client == "⬅ Back":
            return

        client_dir = results_base / sel_client.split(" ", 1)[1]
        targets    = sorted([p for p in client_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower())

        if not targets:
            console.print("[yellow]No targets found for this client.[/yellow]")
            questionary.press_any_key_to_continue().ask()
            continue

        while True:
            draw_header(f"Client: {client_dir.name}")

            target_choices = [f"🎯 {t.name}" for t in targets] + ["⬅ Back"]
            sel_target = questionary.select("Select a target:", choices=target_choices, pointer="➤").ask()

            if sel_target is None or sel_target == "⬅ Back":
                break

            navigate_directory(client_dir / sel_target.split(" ", 1)[1])
