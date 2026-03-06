import subprocess
import platform

class Plugin:
    name = "Ping"
    description = "Ping a target IP or domain"

    def run(self, context=None):
        console = context.get("console") if context else None
        questionary = context.get("questionary") if context else None

        if console:
            console.print("[bold red]Ping Plugin[/bold red]\n")

        if questionary:
            target = questionary.text(
                "Enter IP or domain to ping:"
            ).ask()
        else:
            target = input("Enter IP or domain to ping: ")

        if not target:
            if console:
                console.print("[yellow]No target provided.[/yellow]")
            return

        if console:
            console.print(f"\n[bold]Pinging {target}...[/bold]\n")

        system = platform.system()

        if system == "Windows":
            cmd = ["ping", target]
        else:
            cmd = ["ping", "-c", "4", target]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            for line in process.stdout:
                if console:
                    console.print(line.strip())
                else:
                    print(line.strip())

            process.wait()

        except Exception as e:
            if console:
                console.print(f"[red]Error executing ping: {e}[/red]")
            else:
                print(f"Error executing ping: {e}")