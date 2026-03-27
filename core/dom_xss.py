"""
DOM XSS scanner using Playwright headless browser.
Injects XSS payloads into URL parameters and URL fragments, then monitors
for triggered alert/confirm/prompt dialogs and DOM sinks.

Falls back gracefully if playwright is not installed.
"""
import logging
import re
import urllib.parse
from pathlib import Path

log = logging.getLogger("recon-audit")

_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "';alert(1)//",
    "</script><script>alert(1)</script>",
]

_FRAGMENT_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]


def _playwright_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _get_url_params(url: str) -> list[str]:
    """Return list of parameter names in a URL."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    return list(qs.keys())


def _inject_param(url: str, param: str, payload: str) -> str:
    """Replace the value of *param* in *url* with *payload*."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _inject_fragment(url: str, payload: str) -> str:
    """Append payload as URL fragment."""
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.quote(payload)))


def scan_dom_xss(pages: list[dict], timeout: int = 15) -> list[dict]:
    """
    Run DOM XSS tests via Playwright against crawled pages.

    Returns list of findings:
    [
      {
        "url": "http://example.com/search?q=<payload>",
        "payload": "<img src=x onerror=alert(1)>",
        "trigger": "dialog" | "dom_sink",
        "severity": "HIGH",
        "context": "param:q" | "fragment",
      }
    ]
    """
    if not _playwright_available():
        log.warning("playwright not installed — skipping DOM XSS (pip install playwright && playwright install chromium)")
        return []

    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    findings = []
    seen = set()

    # Collect unique URLs with query parameters + their base URLs for fragment tests
    test_targets = []
    for page in pages:
        url = page.get("url", "")
        if not url or not url.startswith("http"):
            continue
        params = _get_url_params(url)
        for param in params:
            for payload in _PAYLOADS:
                injected = _inject_param(url, param, payload)
                key = (injected, "param:" + param)
                if key not in seen:
                    seen.add(key)
                    test_targets.append({"url": injected, "context": "param:" + param, "payload": payload})
        # Fragment-based
        for payload in _FRAGMENT_PAYLOADS:
            injected = _inject_fragment(url, payload)
            key = (injected, "fragment")
            if key not in seen:
                seen.add(key)
                test_targets.append({"url": injected, "context": "fragment", "payload": payload})

    if not test_targets:
        return []

    log.info("DOM XSS: testing %d URL+payload combinations via Playwright...", len(test_targets))

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        except Exception as e:
            log.warning("Playwright could not launch browser: %s", e)
            return []

        context = browser.new_context(ignore_https_errors=True)

        for target in test_targets:
            test_url = target["url"]
            context_label = target["context"]
            payload = target["payload"]

            triggered = False
            trigger_type = None

            page_obj = context.new_page()
            try:
                def _on_dialog(dialog):
                    nonlocal triggered, trigger_type
                    triggered = True
                    trigger_type = "dialog"
                    dialog.dismiss()

                page_obj.on("dialog", _on_dialog)

                page_obj.goto(test_url, wait_until="domcontentloaded", timeout=timeout * 1000)
                page_obj.wait_for_timeout(800)  # brief wait for JS execution

                # Also check DOM for payload reflection in potentially dangerous sinks
                if not triggered:
                    try:
                        body = page_obj.content()
                        payload_encoded = urllib.parse.quote(payload)
                        if payload in body or payload_encoded in body:
                            # Check if it landed inside a script tag or event handler
                            if re.search(
                                r"<script[^>]*>[^<]*" + re.escape(payload[:20]),
                                body, re.IGNORECASE | re.DOTALL
                            ) or "onerror=" + payload[:10] in body:
                                triggered = True
                                trigger_type = "dom_sink"
                    except Exception:
                        pass

            except PWTimeout:
                pass
            except Exception as e:
                log.debug("Playwright error on %s: %s", test_url, e)
            finally:
                try:
                    page_obj.close()
                except Exception:
                    pass

            if triggered:
                finding = {
                    "url": test_url,
                    "payload": payload,
                    "trigger": trigger_type,
                    "severity": "HIGH",
                    "context": context_label,
                }
                findings.append(finding)
                log.info("DOM XSS triggered: %s [%s] via %s", test_url, trigger_type, context_label)

        try:
            context.close()
            browser.close()
        except Exception:
            pass

    return findings
