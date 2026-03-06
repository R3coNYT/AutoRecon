import logging
import os
from datetime import datetime
from colorlog import ColoredFormatter
from tqdm import tqdm


class TqdmLoggingHandler(logging.Handler):
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
        log_path = os.path.join(output_dir, "recon.log")
    else:
        # fallback legacy
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        legacy_dir = f"results/{target}_{ts}"
        os.makedirs(legacy_dir, exist_ok=True)
        log_path = os.path.join(legacy_dir, f"{target}_{ts}.log")

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s - %(message)s"
    ))

    log.addHandler(file_handler)

    return log