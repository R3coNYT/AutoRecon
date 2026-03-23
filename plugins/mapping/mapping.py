# ======================================================================
# mapping.py — Orchestrator
#
# All heavy logic lives in dedicated sub-modules.
# This file only wires together the Plugin class and the menu loop.
# ======================================================================

import sys
import platform
import questionary
from pathlib import Path

# ── Make the plugin directory importable ───────────────────────────────
_PLUGIN_DIR = Path(__file__).parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

# ── Sub-module imports ─────────────────────────────────────────────────
from ui          import draw_header, safe_ask, console          # noqa: E402
from classifier  import PRIVATE_RANGES                          # noqa: E402
from discovery   import detect_default_gateway                  # noqa: E402
from runner      import run_mapping                             # noqa: E402
from explorer    import explore_results                         # noqa: E402
from pdf_merge   import add_cartography_to_recon               # noqa: E402


class Plugin:
    name        = "Mapping"
    description = "Advanced Information System Mapping & Risk Classification"

    def __init__(self):
        self.plugin_base  = Path(__file__).parent
        self.results_base = self.plugin_base / "results"
        self.results_base.mkdir(exist_ok=True)
        self.default_gw   = None
        if platform.system() != "Windows":
            self.default_gw = detect_default_gateway()

    # ── Menu ────────────────────────────────────────────────────────────────
    def run(self, context=None):
        try:
            while True:
                draw_header("Plugin: MAPPING")

                choice = questionary.select(
                    "Mapping Plugin:",
                    choices=[
                        "Run Mapping",
                        "Explore Results",
                        "Add Cartography to a Recon",
                        "⬅ Back",
                    ],
                    pointer="➤",
                ).ask()

                if choice == "Run Mapping":
                    run_mapping(self.results_base, self.plugin_base, self.default_gw)

                elif choice == "Explore Results":
                    explore_results(self.results_base)

                elif choice == "Add Cartography to a Recon":
                    add_cartography_to_recon(self.results_base)

                else:
                    return

        except KeyboardInterrupt:
            return

