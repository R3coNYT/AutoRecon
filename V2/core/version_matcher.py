import re
from packaging import version as pkg_version

def extract_base_version(v):
    if not v:
        return None

    match = re.search(r"\d+(\.\d+)+", str(v))
    if match:
        return match.group(0)

    return None


def extract_version_conditions(text):
    patterns = [
        r"before\s+([\d\.]+)",
        r"prior to\s+([\d\.]+)",
        r"through\s+([\d\.]+)"
    ]

    conditions = []

    for p in patterns:
        matches = re.findall(p, text.lower())
        for m in matches:
            conditions.append(m)

    return conditions


def is_version_affected(detected_version, cve_summary):

    detected_base = extract_base_version(detected_version)
    if not detected_base:
        return True  # pas sûr → POTENTIAL

    try:
        detected_v = pkg_version.parse(detected_base)
    except:
        return True

    conditions = extract_version_conditions(cve_summary)

    if not conditions:
        return True

    for cond in conditions:
        try:
            cond_v = pkg_version.parse(cond)
        except:
            continue

        # Cas "before X"
        if detected_v < cond_v:
            return True
        else:
            return False

    return True
