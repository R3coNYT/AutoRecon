import os
import re
import shlex
import subprocess
import shutil
import sys
from pathlib import Path

NMAP_BIN = shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"

# On Windows, SYN scan (-sS, the default) requires raw socket access (admin).
# Use TCP connect scan (-sT) instead, which works without elevated privileges.
_WINDOWS = sys.platform == "win32"

# Scan modes:
#   "auto"   — masscan ports if found, else full scan (legacy behaviour)
#   "full"   — all 65535 ports (-p-)
#   "top200" — 200 most common ports
#   "custom" — user-supplied arguments (CUSTOM_NMAP_ARGS)
#   "ports"  — explicit port list (internal, used by "auto")
NMAP_MODES = ("auto", "full", "top200", "custom")


def _env_get(key: str, default: str = "") -> str:
    """Case-insensitive env lookup (accepts full_nmap_scan as well as FULL_NMAP_SCAN)."""
    for k, v in os.environ.items():
        if k.upper() == key:
            return v
    return default


def _env_bool(key: str) -> bool:
    return _env_get(key, "false").strip().lower() in ("true", "1", "yes")


def resolve_nmap_mode_from_env():
    """
    Read the Nmap settings from .env and return (mode, custom_args).
    Priority: CUSTOM_NMAP_SCAN > FULL_NMAP_SCAN > TOP_200_NMAP_SCAN > auto.
    """
    custom_args = _env_get("CUSTOM_NMAP_ARGS").strip()
    # Empty CUSTOM_NMAP_ARGS is valid: runs plain "nmap <target>"
    if _env_bool("CUSTOM_NMAP_SCAN"):
        return "custom", custom_args
    if _env_bool("FULL_NMAP_SCAN"):
        return "full", custom_args
    if _env_bool("TOP_200_NMAP_SCAN"):
        return "top200", custom_args
    return "auto", custom_args


def split_custom_args(custom_args: str) -> list:
    if not _WINDOWS:
        return shlex.split(custom_args)
    # Non-POSIX mode keeps Windows backslashes intact but leaves quotes in tokens
    tokens = shlex.split(custom_args, posix=False)
    # Strip quotes around a whole token ("a b") or an option value (--opt="a b")
    return [re.sub(r"^([^\"']*?)([\"'])(.*)\2$", r"\1\3", t) for t in tokens]


def _build_nmap_cmd(host: str, xml_path, mode: str, ports, skip_discovery: bool, custom_args=None) -> list:
    if mode == "custom":
        cmd = [NMAP_BIN] + split_custom_args(custom_args or "")
        if skip_discovery and "-Pn" not in cmd:
            cmd += ["-Pn"]
        if xml_path:
            cmd += ["-oX", str(xml_path)]
        cmd += [host]
        return cmd

    cmd = [NMAP_BIN, "-sV", "-T4"]

    if skip_discovery:
        cmd += ["-Pn"]

    # On Windows use TCP connect scan to avoid raw-socket privilege errors
    if _WINDOWS:
        cmd += ["-sT"]

    if mode == "full":
        cmd += ["-sC", "-p-"]
    elif mode == "ports" and ports:
        cmd += ["-p", ports]
    else:
        cmd += ["--top-ports", "200"]

    if xml_path:
        cmd += ["-oX", str(xml_path)]
    cmd += [host]
    return cmd


def _run_nmap_cmd(cmd: list, full_scan: bool, timeout, timeout_full) -> str:
    try:
        if full_scan:
            _timeout = timeout_full if timeout_full is not None else (timeout if timeout is not None else 1200)
        else:
            _timeout = timeout if timeout is not None else 300
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=_timeout)
        return result.decode("utf-8", "ignore")
    except subprocess.CalledProcessError as e:
        output = e.output.decode("utf-8", "ignore") if e.output else ""
        if "requires root" in output.lower() or "you requested a scan type" in output.lower():
            return (
                f"[nmap_error] Nmap requires administrator privileges for this scan type. "
                f"Run as admin or use TCP connect scan (-sT).\n{output}"
            )
        return f"[nmap_error] {e}\n{output}"
    except subprocess.TimeoutExpired:
        return "[nmap_error] Nmap scan timed out."
    except Exception as e:
        return f"[nmap_error] {e}"


def _hosts_up(nmap_text: str) -> bool:
    """Return True if nmap reported at least one host up."""
    import re
    # e.g. "Nmap done: 1 IP address (1 host up)"  or  "(0 hosts up)"
    match = re.search(r"\((\d+) hosts? up\)", nmap_text)
    if match:
        return int(match.group(1)) > 0
    # If no summary line (error / empty output) assume something went wrong
    return False


def nmap_service_scan(host: str, output_dir: Path, full_scan=False, ports=None, timeout=None, timeout_full=None,
                      mode=None, custom_args=None):

    # Legacy callers pass full_scan/ports instead of an explicit mode
    if mode is None or mode == "auto":
        mode = "ports" if ports else ("full" if full_scan else "top200")

    safe_host = host.replace("/", "_").replace(":", "_")
    xml_path = ""
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        xml_path = output_dir / f"nmap_{safe_host}.xml"

    # Full and custom scans can be long — they get the longer timeout
    long_scan = mode in ("full", "custom")

    # ── First pass: without -Pn ───────────────────────────────────────────
    cmd = _build_nmap_cmd(host, xml_path, mode, ports, skip_discovery=False, custom_args=custom_args)
    txt_output = _run_nmap_cmd(cmd, long_scan, timeout, timeout_full)

    # ── Retry with -Pn if 0 hosts up ─────────────────────────────────────
    if not _hosts_up(txt_output) and "[nmap_error]" not in txt_output:
        cmd_pn = _build_nmap_cmd(host, xml_path, mode, ports, skip_discovery=True, custom_args=custom_args)
        txt_output = _run_nmap_cmd(cmd_pn, long_scan, timeout, timeout_full)

    return txt_output, xml_path

def infer_scheme_from_nmap(nmap_text: str) -> str:
    if "443/tcp open" in nmap_text:
        return "https"
    if "80/tcp open" in nmap_text:
        return "http"
    return "https"