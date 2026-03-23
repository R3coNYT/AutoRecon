import sys
from pathlib import Path

_PLUGIN_DIR = Path(__file__).parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

import re
import shutil
import questionary

from ui          import draw_header, safe_ask, console
from discovery   import run_nmap_scan
from nmap_parser import parse_nmap_xml, parse_traceroutes
from analytics   import (
    compute_exposure_by_zone,
    compute_criticality_matrix,
    simulate_attack_paths,
    compute_global_score,
)
from exporter    import generate_outputs
from html_map    import generate_html_map
from report      import print_asset_map, print_executive_summary, generate_executive_report, generate_pdf_report
from core.client_folder_select import select_or_create_client_folder


def run_mapping(results_base: Path, plugin_base: Path, default_gw: str | None = None) -> None:
    """
    Full mapping workflow:
      1. Select / create client folder + target
      2. Run Nmap (discovery + deep scan)
      3. Parse results
      4. Compute analytics
      5. Export data + HTML map + PDF/HTML reports
      6. Display Scanopy-like summary
    """
    # ── Target selection ───────────────────────────────────────────────────────
    client_folder = select_or_create_client_folder(results_base)
    if not client_folder:
        return

    existing_targets = sorted(
        [item.name for item in client_folder.iterdir() if item.is_dir()]
    ) if client_folder.exists() else []

    draw_header("Select MAPPING target")

    if existing_targets:
        choice = questionary.select(
            "Select an existing target or add a new one:",
            choices=existing_targets + ["➕ Add a target", "⬅ Back"],
            pointer="➤",
        ).ask()

        if choice is None or choice == "⬅ Back":
            return

        if choice == "➕ Add a target":
            target = _ask_new_target()
            if not target:
                return
        else:
            target_file = client_folder / choice / "target.txt"
            target = target_file.read_text(encoding="utf-8").strip() if target_file.exists() else choice
    else:
        target = _ask_new_target()
        if not target:
            return

    # ── Output directory ───────────────────────────────────────────────────────
    safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    output_dir  = client_folder / safe_target

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "target.txt").write_text(target, encoding="utf-8")

    xml_file = output_dir / "nmap.xml"

    # ── Scan ───────────────────────────────────────────────────────────────────
    draw_header(f"MAPPING  {target}")
    run_nmap_scan(target, xml_file)

    if not xml_file.exists():
        console.print("[red][!] Nmap scan failed — XML file not created.[/red]")
        return

    # ── Parse ──────────────────────────────────────────────────────────────────
    assets = parse_nmap_xml(xml_file, default_gw=default_gw)
    traces = parse_traceroutes(xml_file)

    for a in assets:
        t = traces.get(a["ip"])
        if t:
            a["trace_hops"] = t["hops"]
            a["trace_path"] = t["path"]

    # ── Scanopy-like asset map display ─────────────────────────────────────────
    print_asset_map(assets)

    # ── Analytics (computed once, shared across all outputs) ───────────────────
    exposure      = compute_exposure_by_zone(assets)
    criticality   = compute_criticality_matrix(assets, exposure)
    attack_paths  = simulate_attack_paths(assets)
    global_score  = compute_global_score(assets, criticality)

    # ── Outputs ────────────────────────────────────────────────────────────────
    generate_outputs(assets, output_dir, exposure, criticality, attack_paths)
    generate_html_map(assets, output_dir, plugin_base, exposure, criticality, attack_paths)
    generate_executive_report(assets, exposure, criticality, global_score, output_dir)
    generate_pdf_report(assets, exposure, criticality, global_score, output_dir)

    # ── Summary ────────────────────────────────────────────────────────────────
    print_executive_summary(assets, exposure, criticality, global_score)

    console.print("\n[bold green][+] Mapping complete.[/bold green]")
    console.print(f"[dim]Results saved to: {output_dir}[/dim]\n")
    questionary.press_any_key_to_continue().ask()


def _ask_new_target() -> str | None:
    """Prompt the user for a target string and return it (or None on cancel)."""
    draw_header("Choose MAPPING target")
    console.print(
        "[bold white]Accepted formats:[/bold white]\n"
        "  [bold white]Single IP:[/bold white]   [bold cyan]192.168.1.1[/bold cyan]\n"
        "  [bold white]CIDR range:[/bold white]  [bold cyan]192.168.1.0/24[/bold cyan]\n"
        "  [bold white]Dash range:[/bold white]  [bold cyan]192.168.1.1-254[/bold cyan]\n"
        "  [bold white]Multi IPs:[/bold white]   [bold cyan]192.168.1.1,192.168.1.2[/bold cyan]\n"
        "  [bold white]Domain:[/bold white]      [bold cyan]example.com[/bold cyan]"
    )
    return questionary.text("Enter target:").ask() or None
