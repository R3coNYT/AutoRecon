import subprocess
import json
import shutil

NUCLEI_BIN = shutil.which("nuclei") or "C:/Tools/bin/nuclei.exe"

def run_nuclei(targets, output_dir=None, target_name=None, severity=None):

    if isinstance(targets, list):
        targets = "\n".join(targets)

    cmd = [
        NUCLEI_BIN,
        "-json",
        "-silent",
    ]

    if severity:
        cmd += ["-severity", severity]

    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        stdout, _ = process.communicate(targets)

    except Exception as e:
        print(f"[nuclei_error] {e}")
        return []

    vulns = []

    for line in stdout.splitlines():
        try:
            vulns.append(json.loads(line))
        except:
            pass

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

        if target_name:
            file_name = f"nuclei_{target_name}.json"
        else:
            file_name = "nuclei.json"

        with open(output_dir / file_name, "w", encoding="utf-8") as f:
            json.dump(vulns, f, indent=2)

    return vulns