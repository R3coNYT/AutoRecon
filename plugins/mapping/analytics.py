def compute_exposure_by_zone(assets: list) -> dict:
    """
    Compute heuristic exposure scores per network zone.

    Returns a dict keyed by zone name with:
        hosts, open_services_total, risky_ports_total,
        exposure_score, exposure_score_avg
    """
    risky_ports = {22, 3389, 445, 21, 25, 1433, 1521, 3306, 5432, 27017, 6379, 9200}
    exposure: dict = {}

    for a in assets:
        zone = a["zone"]
        exposure.setdefault(zone, {
            "hosts":               0,
            "open_services_total": 0,
            "risky_ports_total":   0,
            "exposure_score":      0,
        })

        exposure[zone]["hosts"] += 1
        svcs = a.get("services", [])
        exposure[zone]["open_services_total"] += len(svcs)

        rp = 0
        for s in svcs:
            try:
                if int(s["port"]) in risky_ports:
                    rp += 1
            except Exception:
                pass
        exposure[zone]["risky_ports_total"] += rp

        score = len(svcs) + (3 * rp)
        if zone != "LAN":
            score += 5
        exposure[zone]["exposure_score"] += score

    for z in exposure:
        h = max(exposure[z]["hosts"], 1)
        exposure[z]["exposure_score_avg"] = round(exposure[z]["exposure_score"] / h, 2)

    return exposure


def compute_criticality_matrix(assets: list, exposure_by_zone: dict) -> dict:
    """
    Compute a criticality matrix (Impact × Exposure) for every asset.

    Returns a dict with counts per level and sorted 'items' list.
    """
    impact_map = {
        "Domain Controller":     5,
        "Database Server":       4,
        "Web Server":            3,
        "Windows Server":        3,
        "Linux Server":          3,
        "Workstation / Unknown": 2,
    }

    matrix: dict = {"low": 0, "medium": 0, "high": 0, "critical": 0, "items": []}

    for a in assets:
        impact = impact_map.get(a["classification"], 2)
        zone   = a["zone"]
        zone_exposure_avg = exposure_by_zone.get(zone, {}).get("exposure_score_avg", 0)

        raw = (a["risk_score"] * 0.7) + (zone_exposure_avg * 0.3)
        if   raw < 2.5: exposure_level = 1
        elif raw < 4.5: exposure_level = 2
        elif raw < 6.5: exposure_level = 3
        elif raw < 8.0: exposure_level = 4
        else:           exposure_level = 5

        criticality_score = impact * exposure_level  # 1..25

        if   criticality_score >= 20: level = "critical"
        elif criticality_score >= 14: level = "high"
        elif criticality_score >= 8:  level = "medium"
        else:                         level = "low"

        matrix[level] += 1
        matrix["items"].append({
            "ip":                a["ip"],
            "zone":              zone,
            "classification":    a["classification"],
            "impact":            impact,
            "exposure_level":    exposure_level,
            "risk_score":        a["risk_score"],
            "criticality_score": criticality_score,
            "criticality_level": level,
        })

    matrix["items"].sort(key=lambda x: x["criticality_score"], reverse=True)
    return matrix


def simulate_attack_paths(assets: list) -> list:
    """
    Simulate logical lateral-movement attack paths based on host roles.

    Scenarios:
      1. DMZ compromise → Domain Controller
      2. Web compromise → Database access
      3. DMZ pivot → DB → Domain Controller
    """
    dc  = [a for a in assets if a["classification"] == "Domain Controller"]
    win = [a for a in assets if a["classification"] == "Windows Server"]
    web = [a for a in assets if a["classification"] == "Web Server"]

    def is_db(a):
        for s in a.get("services", []):
            try:
                if int(s["port"]) in (3306, 5432):
                    return True
            except Exception:
                pass
        return False

    db  = [a for a in assets if is_db(a)]
    dmz = [a for a in assets if a["zone"] != "LAN"]
    lan = [a for a in assets if a["zone"] == "LAN"]

    adj: dict = {}

    def add_edge(u, v, reason):
        adj.setdefault(u, [])
        adj[u].append((v, reason))

    for d in dc:
        for w in win:
            add_edge(d["ip"], w["ip"], "AD/DC → Windows")
            add_edge(w["ip"], d["ip"], "Windows → AD/DC (auth)")

    for w in web:
        for dbase in db:
            add_edge(w["ip"], dbase["ip"], "Web → DB")
            add_edge(dbase["ip"], w["ip"], "DB → Web (app dep)")

    admin_ports = {22, 3389, 445}
    for x in dmz:
        for y in lan:
            ok = any(
                int(s["port"]) in admin_ports
                for s in y.get("services", [])
                if s.get("port", "").isdigit()
            )
            if ok:
                add_edge(x["ip"], y["ip"], "DMZ pivot → LAN admin surface")

    def find_paths(starts, targets, max_depth=5):
        paths = []
        target_set = {t["ip"] for t in targets}
        for s in starts:
            start = s["ip"]
            q = [(start, [start], [])]
            while q:
                node, path, reasons = q.pop(0)
                if len(path) > max_depth:
                    continue
                if node in target_set and node != start:
                    paths.append({"path": path, "reasons": reasons})
                    continue
                for (nxt, reason) in adj.get(node, []):
                    if nxt not in path:
                        q.append((nxt, path + [nxt], reasons + [reason]))
        return paths

    scenarios = []

    if dmz and dc:
        scenarios.append({
            "name":  "DMZ compromise → Domain Controller",
            "paths": find_paths(dmz, dc, max_depth=6),
        })

    if web and db:
        scenarios.append({
            "name":  "Web compromise → Database access",
            "paths": find_paths(web, db, max_depth=3),
        })

    if dmz and db and dc:
        p1 = find_paths(dmz, db, max_depth=4)
        p2 = find_paths(db,  dc, max_depth=4)
        combined = [
            {
                "path":    a["path"] + b["path"][1:],
                "reasons": a["reasons"] + b["reasons"],
            }
            for a in p1
            for b in p2
            if a["path"][-1] == b["path"][0]
        ]
        scenarios.append({"name": "DMZ pivot → DB → Domain Controller", "paths": combined})

    for sc in scenarios:
        uniq = {
            "->".join(p["path"]): p
            for p in sc["paths"]
        }
        sc["paths"] = list(uniq.values())[:25]

    return scenarios


def compute_global_score(assets: list, criticality: dict) -> float:
    """
    Compute a global security score out of 100.
    Lower is worse.
    """
    if not assets:
        return 100.0

    avg_risk       = sum(a["risk_score"] for a in assets) / len(assets)
    critical_ratio = (criticality["critical"] + criticality["high"]) / len(assets)

    score = 100.0 - (avg_risk * 5) - (critical_ratio * 40)
    return max(round(score, 2), 0.0)
