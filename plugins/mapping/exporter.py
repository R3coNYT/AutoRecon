import json
import csv
from pathlib import Path
from rich.console import Console

console = Console()


def generate_outputs(
    assets:       list,
    output_dir:   Path,
    exposure:     dict,
    criticality:  dict,
    attack_paths: list,
) -> None:
    """
    Write all JSON and CSV exports to *output_dir*.
    Analytics (exposure, criticality, attack_paths) are pre-computed by the caller.
    """
    output_dir = Path(output_dir)

    # ── Basic inventory ──────────────────────────────────────────────────────
    with open(output_dir / "inventory.json", "w", encoding="utf-8") as f:
        json.dump(assets, f, indent=4)

    with open(output_dir / "inventory.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Zone", "Type", "Risk Score"])
        for a in assets:
            writer.writerow([a["ip"], a["zone"], a["classification"], a["risk_score"]])

    # ── Traceroutes ──────────────────────────────────────────────────────────
    traceroutes = {a["ip"]: a.get("trace_path") for a in assets if a.get("trace_path")}
    with open(output_dir / "traceroutes.json", "w", encoding="utf-8") as f:
        json.dump(traceroutes, f, indent=4)

    # ── Analytics JSONs ──────────────────────────────────────────────────────
    with open(output_dir / "exposure_by_zone.json", "w", encoding="utf-8") as f:
        json.dump(exposure, f, indent=4)

    with open(output_dir / "criticality_matrix.json", "w", encoding="utf-8") as f:
        json.dump(criticality, f, indent=4)

    with open(output_dir / "attack_paths.json", "w", encoding="utf-8") as f:
        json.dump(attack_paths, f, indent=4)

    # ── Exposure CSV ─────────────────────────────────────────────────────────
    with open(output_dir / "exposure_by_zone.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Zone", "Hosts", "Open Services", "Risky Ports", "Exposure Score", "Exposure Avg"])
        for z, v in exposure.items():
            writer.writerow([
                z,
                v.get("hosts",               0),
                v.get("open_services_total",  0),
                v.get("risky_ports_total",    0),
                v.get("exposure_score",       0),
                v.get("exposure_score_avg",   0),
            ])

    # ── Criticality CSV (top 50) ─────────────────────────────────────────────
    with open(output_dir / "criticality_top.csv", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Zone", "Type", "Impact", "Exposure", "Risk Score", "Criticality Score", "Level"])
        for item in criticality.get("items", [])[:50]:
            writer.writerow([
                item.get("ip"),
                item.get("zone"),
                item.get("classification"),
                item.get("impact"),
                item.get("exposure_level"),
                item.get("risk_score"),
                item.get("criticality_score"),
                item.get("criticality_level"),
            ])

    console.print("[green][+] Data exports generated (JSON + CSV).[/green]")
