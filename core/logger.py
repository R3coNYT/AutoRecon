import logging
import sys
import os
from datetime import datetime
from colorlog import ColoredFormatter
from tqdm import tqdm
from pathlib import Path

if sys.platform == "win32":
    try:
        os.system("chcp 65001 > nul")
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except:
        pass

class TqdmLoggingHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)

def setup_logging(target, output_dir=None):
    log = logging.getLogger("recon-audit")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    
    if output_dir:
        output_dir = Path(output_dir)

    # =========================
    # Console (tqdm-compatible)
    # =========================
    console_handler = TqdmLoggingHandler()
    console_handler.setLevel(logging.INFO)

    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s] %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        }
    )

    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)

    # =========================
    # File logging (CUSTOM DIR)
    # =========================
    if output_dir:
        log_output_dir = output_dir / "logs"
        log_output_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_output_dir / "recon.log"
    else:
        # fallback legacy
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        legacy_dir = Path("results") / f"{target}_{ts}"
        legacy_dir.mkdir(parents=True, exist_ok=True)
        log_path = legacy_dir / f"{target}_{ts}.log"

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s - %(message)s"
    ))

    log.addHandler(file_handler)

    return log