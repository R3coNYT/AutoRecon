import time
from contextlib import contextmanager
import logging

log = logging.getLogger("recon-audit")

@contextmanager
def step_timer(step_name: str):
    start = time.time()
    log.info("▶ %s started...", step_name)
    yield
    elapsed = round(time.time() - start, 2)
    log.info("✔ %s finished in %ss", step_name, elapsed)
