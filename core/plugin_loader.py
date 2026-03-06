import os
import json
import importlib.util

PLUGINS_DIR = "plugins"

def load_plugins():
    plugins = []

    if not os.path.exists(PLUGINS_DIR):
        return plugins

    for folder in os.listdir(PLUGINS_DIR):
        path = os.path.join(PLUGINS_DIR, folder)
        manifest_path = os.path.join(path, "manifest.json")

        if os.path.isdir(path) and os.path.exists(manifest_path):
            with open(manifest_path, "r") as f:
                manifest = json.load(f)

            plugin_file = os.path.join(path, manifest["entry"])

            spec = importlib.util.spec_from_file_location(
                manifest["name"], plugin_file
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            plugin_class = getattr(module, manifest["class"])
            plugins.append(plugin_class())

    return plugins