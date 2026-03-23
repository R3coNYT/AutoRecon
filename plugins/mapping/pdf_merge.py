import sys
from pathlib import Path

_PLUGIN_DIR = Path(__file__).parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

import re
import shutil
from datetime import datetime
from io import BytesIO

import questionary
from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas as rl_canvas

from ui import draw_header, safe_ask, console
from core.report_pdf import _load_personalization


# ── Helpers ────────────────────────────────────────────────────────────────────

def safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", s or "")


def list_mapping_runs(results_base: Path) -> list:
    """Return a list of mapping runs that have an executive_report.pdf."""
    runs = []
    if not results_base.exists():
        return runs
    for client_dir in sorted([p for p in results_base.iterdir() if p.is_dir()], key=lambda p: p.name.lower()):
        for target_dir in sorted([p for p in client_dir.iterdir() if p.is_dir()], key=lambda p: p.name.lower()):
            mapping_pdf = target_dir / "executive_report.pdf"
            if mapping_pdf.exists():
                runs.append({
                    "client": client_dir.name,
                    "target": target_dir.name,
                    "path":   target_dir,
                })
    return runs


def find_recon_pdf_candidates(client_name: str, target_name: str) -> dict:
    """Search common locations for a matching Recon PDF."""
    candidates = {"match": None, "all_pdfs": [], "searched_roots": []}

    roots = []
    try:
        roots.append(Path(__file__).resolve().parents[2] / "results")
    except Exception:
        pass
    roots.append(Path.cwd() / "results")
    roots.append(Path("results").resolve())

    unique_roots: list = []
    seen_roots:   set  = set()
    for r in roots:
        rr  = r.resolve()
        key = str(rr).lower()
        if key not in seen_roots:
            seen_roots.add(key)
            unique_roots.append(rr)

    seen_pdf: set = set()

    for root in unique_roots:
        candidates["searched_roots"].append(str(root))
        client_dir = root / client_name
        if not (client_dir.exists() and client_dir.is_dir()):
            continue

        direct = client_dir / target_name / "report.pdf"
        if direct.exists() and candidates["match"] is None:
            candidates["match"] = direct

        for pdf in client_dir.rglob("*.pdf"):
            p = pdf.resolve()
            k = str(p).lower()
            if k not in seen_pdf:
                seen_pdf.add(k)
                candidates["all_pdfs"].append(p)

    return candidates


def find_insert_index_before_author(recon_reader: PdfReader) -> int:
    """Return the page index just before an 'Author' or signature page."""
    needles = ["Author", "Analysis report prepared by"]
    for i, page in enumerate(recon_reader.pages):
        try:
            txt = page.extract_text() or ""
        except Exception:
            txt = ""
        if any(n.lower() in txt.lower() for n in needles):
            return i
    return len(recon_reader.pages)


def create_footer_overlay(page_number: int) -> PdfReader:
    """Stamp a page-number + identity footer onto a PDF page overlay."""
    packet = BytesIO()
    c      = rl_canvas.Canvas(packet, pagesize=A4)
    width, height = A4

    if page_number > 1:
        logo_path, sign_path, name = _load_personalization()

        footer_y = 1.2 * cm
        line_y   = 1.8 * cm

        c.setFillColor(colors.white)
        c.rect(0, 0, width, 2.5 * cm, fill=1, stroke=0)

        c.setStrokeColor(colors.lightgrey)
        c.setLineWidth(0.5)
        c.line(2 * cm, line_y, width - 2 * cm, line_y)

        if name:
            c.setFont("Helvetica", 8)
            c.setFillColor(colors.grey)
            c.drawString(2 * cm, footer_y, name)

        if logo_path:
            try:
                logo_w = logo_h = 0.9 * cm
                c.drawImage(
                    logo_path,
                    (width / 2) - (logo_w / 2),
                    footer_y - 0.5 * cm,
                    width=logo_w, height=logo_h,
                    preserveAspectRatio=True, mask="auto",
                )
            except Exception:
                pass

        c.setFont("Helvetica", 8)
        c.setFillColor(colors.grey)
        c.drawRightString(width - 2 * cm, footer_y, f"Page {page_number}")

    c.showPage()
    c.save()
    packet.seek(0)
    return PdfReader(packet)


def merge_mapping_into_recon_pdf(recon_pdf: Path, mapping_pdf: Path) -> Path:
    """
    Insert the mapping PDF pages into the recon PDF (before the author page).
    Creates a timestamped backup before writing.
    Returns the backup path.
    """
    if not recon_pdf.exists():
        raise FileNotFoundError(f"Recon PDF not found: {recon_pdf}")
    if not mapping_pdf.exists():
        raise FileNotFoundError(f"Mapping PDF not found: {mapping_pdf}")

    ts          = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = recon_pdf.with_suffix(f".backup_{ts}.pdf")
    shutil.copy2(recon_pdf, backup_path)

    recon_reader   = PdfReader(str(recon_pdf))
    mapping_reader = PdfReader(str(mapping_pdf))
    insert_at      = find_insert_index_before_author(recon_reader)

    final_pages = (
        list(recon_reader.pages[:insert_at])
        + list(mapping_reader.pages)
        + list(recon_reader.pages[insert_at:])
    )

    writer        = PdfWriter()
    page_counter  = 1

    for page in final_pages:
        overlay_page = create_footer_overlay(page_counter).pages[0]
        page.merge_page(overlay_page)
        writer.add_page(page)
        page_counter += 1

    with open(recon_pdf, "wb") as f:
        writer.write(f)

    return backup_path


# ── Interactive CLI flow ───────────────────────────────────────────────────────

def add_cartography_to_recon(results_base: Path) -> None:
    """Interactive CLI wizard to merge a mapping PDF into an existing Recon PDF."""
    runs = list_mapping_runs(results_base)

    if not runs:
        draw_header("Add Cartography to a Recon")
        console.print("[yellow]No mapping cartography found yet.[/yellow]")
        questionary.press_any_key_to_continue().ask()
        return

    draw_header("Add Cartography to a Recon")
    choices = [f"{r['client']}  |  {r['target']}" for r in runs]

    selected = safe_ask(
        questionary.select(
            "Select a cartography (mapping) to attach:",
            choices=choices + ["⬅ Back"],
            pointer="➤",
        )
    )

    if selected == "⬅ Back":
        return

    idx         = choices.index(selected)
    run         = runs[idx]
    mapping_pdf = run["path"] / "executive_report.pdf"
    cands       = find_recon_pdf_candidates(run["client"], run["target"])
    match       = cands["match"]
    all_pdfs    = cands["all_pdfs"]
    searched_roots = [Path(p) for p in cands.get("searched_roots", [])]

    recon_pdf = None

    if match:
        draw_header("Recon PDF Found")
        if questionary.confirm(
            f"Found matching Recon PDF:\n{match}\n\nAttach cartography to this PDF?",
            default=True,
        ).ask():
            recon_pdf = match

    if recon_pdf is None:
        draw_header("Select Recon PDF")
        if not all_pdfs:
            console.print(f"[red]No PDF found for client '{run['client']}'.[/red]")
            for root in searched_roots:
                console.print(f" - {root}")
            questionary.press_any_key_to_continue().ask()
            return

        display_map: dict = {}
        for p in all_pdfs:
            label = str(p)
            for root in searched_roots:
                try:
                    label = str(p.relative_to(root))
                    break
                except Exception:
                    pass
            if label in display_map:
                label = f"{label}  ({p})"
            display_map[label] = p

        pick = questionary.select(
            "Select a Recon PDF to attach cartography to:",
            choices=list(display_map.keys()) + ["⬅ Back"],
            pointer="➤",
        ).ask()

        if pick == "⬅ Back":
            return
        recon_pdf = display_map[pick]

    draw_header("Merging PDFs")
    console.print("[*] Recon PDF:   ", recon_pdf)
    console.print("[*] Mapping PDF: ", mapping_pdf)

    try:
        backup = merge_mapping_into_recon_pdf(recon_pdf, mapping_pdf)
        console.print("[green][+] Cartography added successfully![/green]")
        console.print(f"[green][+] Backup: {backup}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Failed to merge PDFs: {e}[/red]")

    questionary.press_any_key_to_continue().ask()
