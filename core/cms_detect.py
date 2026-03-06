def detect_cms(headers: dict, html_snippet: str):
    h = {k.lower(): str(v) for k, v in (headers or {}).items()}
    html = (html_snippet or "").lower()

    cms = []
    # WordPress
    if "wp-content" in html or "wp-includes" in html or "wordpress" in html:
        cms.append("WordPress")
    # Joomla
    if "joomla" in html or "com_content" in html or "mosconfig" in html:
        cms.append("Joomla")
    # Drupal
    if "drupal" in html or "sites/all" in html or "drupal-settings-json" in html:
        cms.append("Drupal")

    # generic hints
    if "x-powered-by" in h:
        cms.append(f"X-Powered-By: {h['x-powered-by']}")
    if "server" in h:
        cms.append(f"Server: {h['server']}")

    return sorted(set(cms))
