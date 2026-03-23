import sys
from pathlib import Path

_PLUGIN_DIR = Path(__file__).parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

from io import BytesIO
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table as RLTable, TableStyle
from reportlab.lib import colors, pagesizes
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, cm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.lib.pagesizes import A4
from classifier import HOST_ICONS, get_risk_style

console = Console()

# ── Scanopy-like asset map (shown right after nmap parse) ─────────────────────

def print_asset_map(assets: list) -> None:
    """
    Display a Scanopy-inspired rich table of all discovered assets,
    colour-coded by risk score.
    """
    if not assets:
        console.print("[yellow]No assets to display.[/yellow]")
        return

    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        expand=False,
        title_style="bold magenta",
    )
    tbl.add_column("IP Address",  style="bold white",  no_wrap=True, min_width=16)
    tbl.add_column("Type",                             min_width=24)
    tbl.add_column("Zone",        justify="center",    min_width=16)
    tbl.add_column("Risk",        justify="center",    min_width=6)
    tbl.add_column("Open Ports",  style="dim")

    for a in sorted(assets, key=lambda x: x["risk_score"], reverse=True):
        icon       = HOST_ICONS.get(a["classification"], "❓ ")
        risk_style = get_risk_style(a["risk_score"])
        ports      = ", ".join(s["port"] for s in a.get("services", []))
        zone_style = "bold red" if a["zone"] != "LAN" else "cyan"

        tbl.add_row(
            a["ip"],
            f"{icon}{a['classification']}",
            f"[{zone_style}]{a['zone']}[/{zone_style}]",
            f"[{risk_style}]{a['risk_score']}[/{risk_style}]",
            ports or "—",
        )

    console.print(
        Panel(
            tbl,
            title=f"[bold magenta]🗺️   Asset Map — {len(assets)} host(s)[/bold magenta]",
            border_style="magenta",
            expand=False,
        )
    )


# ── Executive summary (rich panels) ──────────────────────────────────────────

def print_executive_summary(
    assets:      list,
    exposure:    dict,
    criticality: dict,
    global_score: float,
) -> None:
    """Print a Scanopy-inspired executive summary using Rich panels."""

    # ── Score band ────────────────────────────────────────────────────────────
    if global_score >= 80:
        score_style  = "bold green"
        posture_text = "✅  Security posture: GOOD"
        posture_style = "green"
    elif global_score >= 60:
        score_style  = "bold yellow"
        posture_text = "⚠️  Security posture: MODERATE"
        posture_style = "yellow"
    else:
        score_style  = "bold red"
        posture_text = "🚨  Security posture: CRITICAL"
        posture_style = "red"

    # ── Criticality mini-table ────────────────────────────────────────────────
    crit_tbl = Table(box=box.SIMPLE, show_header=False, expand=False, padding=(0, 1))
    crit_tbl.add_column(justify="left",  style="dim")
    crit_tbl.add_column(justify="right")
    crit_tbl.add_row("Total assets",   f"[bold white]{len(assets)}[/bold white]")
    crit_tbl.add_row("Critical",       f"[bold red]{criticality['critical']}[/bold red]")
    crit_tbl.add_row("High",           f"[bold yellow]{criticality['high']}[/bold yellow]")
    crit_tbl.add_row("Medium",         f"[bold cyan]{criticality['medium']}[/bold cyan]")
    crit_tbl.add_row("Low",            f"[bold green]{criticality['low']}[/bold green]")

    # ── Exposure mini-table ───────────────────────────────────────────────────
    exp_tbl = Table(box=box.SIMPLE_HEAD, show_header=True, expand=False, padding=(0, 1))
    exp_tbl.add_column("Zone",     style="bold white")
    exp_tbl.add_column("Hosts",    justify="center")
    exp_tbl.add_column("Risky",    justify="center")
    exp_tbl.add_column("Avg Exp.", justify="center")
    for zone, v in exposure.items():
        z_style = "bold red" if zone != "LAN" else "cyan"
        exp_tbl.add_row(
            f"[{z_style}]{zone}[/{z_style}]",
            str(v["hosts"]),
            str(v["risky_ports_total"]),
            str(v["exposure_score_avg"]),
        )

    score_line = Text(f"  Global Security Score: {global_score}/100", style=score_style)
    body = Text()
    body.append(f"\n{posture_text}\n", style=posture_style)

    console.print()
    console.rule("[bold red]EXECUTIVE SUMMARY[/bold red]")
    console.print(score_line)
    console.print(body)
    console.print(Panel(crit_tbl, title="[bold]Criticality Breakdown[/bold]",  border_style="red",   expand=False))
    console.print(Panel(exp_tbl,  title="[bold]Exposure by Zone[/bold]",       border_style="blue",  expand=False))

    # ── Top 5 critical assets ─────────────────────────────────────────────────
    top = criticality.get("items", [])[:5]
    if top:
        top_tbl = Table(box=box.SIMPLE_HEAD, show_header=True, expand=False)
        top_tbl.add_column("IP",    style="bold white", no_wrap=True)
        top_tbl.add_column("Type",  style="dim")
        top_tbl.add_column("Zone",  justify="center")
        top_tbl.add_column("Score", justify="center")
        top_tbl.add_column("Level", justify="center")
        LEVEL_STYLE = {"critical": "bold red", "high": "bold yellow", "medium": "bold cyan", "low": "bold green"}
        for it in top:
            style = LEVEL_STYLE.get(it["criticality_level"], "")
            top_tbl.add_row(
                it["ip"],
                HOST_ICONS.get(it["classification"], "❓ ") + it["classification"],
                it["zone"],
                f"[{style}]{it['criticality_score']}[/{style}]",
                f"[{style}]{it['criticality_level'].upper()}[/{style}]",
            )
        console.print(Panel(top_tbl, title="[bold]Top 5 Critical Assets[/bold]", border_style="yellow", expand=False))

    console.rule()


# ── HTML executive report ─────────────────────────────────────────────────────

def generate_executive_report(
    assets:       list,
    exposure:     dict,
    criticality:  dict,
    global_score: float,
    output_dir:   Path,
) -> None:
    output_dir  = Path(output_dir)
    report_file = output_dir / "executive_report.html"
    top5        = criticality["items"][:5]

    html = f"""<html>
<head>
<title>Executive Security Report</title>
<style>
body {{ font-family: Arial; background:#0f111a; color:white; padding:40px; }}
h1   {{ color:#ff4c4c; }}
.score {{ font-size:28px; margin:20px 0; }}
table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
td, th {{ border-bottom:1px solid #333; padding:8px; }}
</style>
</head>
<body>
<h1>Information System Security Executive Report</h1>
<div class="score">Global Security Score: <b>{global_score}/100</b></div>
<h2>Summary</h2>
<ul>
  <li>Total assets discovered: {len(assets)}</li>
  <li>Critical assets: {criticality['critical']}</li>
  <li>High risk assets: {criticality['high']}</li>
  <li>Medium risk assets: {criticality['medium']}</li>
  <li>Low risk assets: {criticality['low']}</li>
</ul>
<h2>Top 5 Critical Assets</h2>
<table>
<tr><th>IP</th><th>Type</th><th>Zone</th><th>Criticality Score</th></tr>
"""
    for item in top5:
        html += (
            f"<tr><td>{item['ip']}</td><td>{item['classification']}</td>"
            f"<td>{item['zone']}</td><td>{item['criticality_score']}</td></tr>\n"
        )

    html += """</table>
<h2>Recommendations</h2>
<ul>
  <li>Reduce exposed administrative services (RDP, SSH, SMB).</li>
  <li>Segment DMZ from LAN strictly.</li>
  <li>Apply patch management on high critical assets.</li>
  <li>Restrict lateral movement paths.</li>
</ul>
</body>
</html>
"""

    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html)

    console.print(f"[+] Executive HTML report: {report_file}")


# ── PDF executive report ──────────────────────────────────────────────────────

def generate_pdf_report(
    assets:       list,
    exposure:     dict,
    criticality:  dict,
    global_score: float,
    output_dir:   Path,
) -> None:
    output_dir = Path(output_dir)
    pdf_path   = output_dir / "executive_report.pdf"

    doc      = SimpleDocTemplate(str(pdf_path), pagesize=pagesizes.A4)
    styles   = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Information System Security Executive Report", styles["Heading1"]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f"<b>Global Security Score:</b> {global_score}/100", styles["Heading2"]))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph("<b>Summary</b>", styles["Heading2"]))
    elements.append(Spacer(1, 6))

    summary_data = [
        ["Total assets",     len(assets)],
        ["Critical assets",  criticality["critical"]],
        ["High risk assets", criticality["high"]],
        ["Medium risk",      criticality["medium"]],
        ["Low risk",         criticality["low"]],
    ]
    summary_tbl = RLTable(summary_data, colWidths=[3 * inch, 2 * inch])
    summary_tbl.setStyle(TableStyle([
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("GRID",      (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN",     (1, 0), (-1, -1), "CENTER"),
    ]))
    elements += [summary_tbl, Spacer(1, 8)]

    elements.append(Paragraph("<b>Exposure by Zone</b>", styles["Heading2"]))
    elements.append(Spacer(1, 6))
    exposure_data = [["Zone", "Hosts", "Open", "Risky", "Avg Score"]]
    for z, v in exposure.items():
        exposure_data.append([z, v["hosts"], v["open_services_total"], v["risky_ports_total"], v["exposure_score_avg"]])
    exp_tbl = RLTable(exposure_data, repeatRows=1)
    exp_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN",      (1, 1), (-1, -1), "CENTER"),
    ]))
    elements += [exp_tbl, Spacer(1, 8)]

    elements.append(Paragraph("<b>Top 10 Critical Assets</b>", styles["Heading2"]))
    elements.append(Spacer(1, 6))
    crit_data = [["IP", "Type", "Zone", "Score"]]
    for item in criticality["items"][:10]:
        crit_data.append([item["ip"], item["classification"], item["zone"], item["criticality_score"]])
    crit_tbl = RLTable(crit_data, repeatRows=1)
    crit_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN",      (3, 1), (3, -1), "CENTER"),
    ]))
    elements += [crit_tbl, Spacer(1, 8)]

    elements.append(Paragraph("<b>Security Recommendations</b>", styles["Heading2"]))
    elements.append(Spacer(1, 6))
    for rec in [
        "• Reduce exposed administrative services (RDP, SSH, SMB).",
        "• Strictly segment DMZ from LAN.",
        "• Apply patch management on high critical assets.",
        "• Monitor lateral movement paths.",
    ]:
        elements.append(Paragraph(rec, styles["Normal"]))
        elements.append(Spacer(1, 4))

    # Link to topology map
    elements += [Spacer(1, 8), Paragraph("<b>Interactive Topology Map</b>", styles["Heading2"]), Spacer(1, 6)]
    topology_url = f"file:///{(output_dir / 'topology.html').resolve()}"
    link_style = ParagraphStyle(
        "link_style", parent=styles["Normal"], textColor=colors.blue, underline=True
    )
    elements.append(
        Paragraph(f'<link href="{topology_url}"><b>🌐 Open Interactive Topology Map</b></link>', link_style)
    )

    doc.build(elements)
    console.print(f"[green][+] PDF report: {pdf_path}[/green]")
