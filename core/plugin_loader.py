import json
import importlib.util
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PLUGINS_DIR = BASE_DIR / "plugins"

def load_plugins():
    plugins = []

    if not PLUGINS_DIR.exists():
        return plugins

    for folder in PLUGINS_DIR.iterdir():

        manifest_path = folder / "manifest.json"

        if folder.is_dir() and manifest_path.exists():

            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)

            plugin_file = folder / manifest["entry"]

            spec = importlib.util.spec_from_file_location(
                manifest["name"], plugin_file
            )

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            plugin_class = getattr(module, manifest["class"])

            plugins.append(plugin_class())

    return plugins