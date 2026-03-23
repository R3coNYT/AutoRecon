import subprocess
import platform
import shutil
from pathlib import Path
from rich.console import Console

console = Console()


def draw_header(title: str = "Results Browser") -> None:
    from core.banner import print_banner
    console.clear()
    print_banner()
    console.rule("[bold red]AutoRecon Console[/bold red]")
    console.print(f"[bold red]{title}[/bold red]")


def safe_ask(q):
    result = q.ask()
    if result is None:
        raise KeyboardInterrupt
    return result


def open_file_cross_platform(path) -> None:
    path = Path(path)
    if platform.system() == "Windows":
        subprocess.run(["cmd", "/c", "start", "", str(path)], check=False)
    elif platform.system() == "Darwin":
        subprocess.run(["open", str(path)], check=False)
    else:
        if shutil.which("xdg-open"):
            subprocess.Popen(
                ["xdg-open", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        elif shutil.which("chromium"):
            subprocess.Popen(
                ["chromium", "--new-tab", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        else:
            subprocess.Popen(
                ["firefox", "--new-tab", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
