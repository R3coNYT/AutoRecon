import json
from flask import Flask, render_template, abort

def create_app(report_json_path: str):
    app = Flask(__name__, template_folder="templates", static_folder="static")

    def load_report():
        try:
            with open(report_json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    @app.get("/")
    def index():
        rep = load_report()
        if not rep:
            abort(500)
        subs = rep.get("subdomains", {})
        return render_template("index.html", report=rep, subdomains=subs)

    @app.get("/sub/<name>")
    def sub_report(name):
        rep = load_report()
        if not rep:
            abort(500)
        data = rep.get("subdomains", {}).get(name)
        if not data:
            abort(404)
        return render_template("report.html", sub=name, data=data, report=rep)

    return app
