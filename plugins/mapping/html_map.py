import json
from pathlib import Path
from rich.console import Console

console = Console()


def generate_html_map(
    assets:       list,
    output_dir:   Path,
    plugin_base:  Path,
    exposure:     dict,
    criticality:  dict,
    attack_paths: list,
) -> None:
    """
    Generate the interactive Vis-Network topology HTML file.
    All analytics (exposure, criticality, attack_paths) are pre-computed by the caller.
    """
    output_dir  = Path(output_dir)
    plugin_base = Path(plugin_base)
    html_file   = output_dir / "topology.html"

    static_dir = plugin_base / "static"
    static_dir.mkdir(exist_ok=True)

    nodes: list = []
    edges: list = []
    edge_ids    = 0
    db_ports    = [3306, 5432]

    # ── Nodes ────────────────────────────────────────────────────────────────
    for asset in assets:
        color = (
            "#ff4c4c" if asset["risk_score"] >= 7
            else "#ffae42" if asset["risk_score"] >= 4
            else "#4caf50"
        )
        nodes.append({
            "id":       asset["ip"],
            "label":    asset["ip"],
            "group":    asset["zone"],
            "color":    color,
            "type":     asset["classification"],
            "risk":     asset["risk_score"],
            "services": [s.get("port") for s in asset.get("services", [])],
            "title": (
                f"IP: {asset['ip']}\n"
                f"Zone: {asset['zone']}\n"
                f"Type: {asset['classification']}\n"
                f"Risk Score: {asset['risk_score']}\n"
                f"Services: {', '.join(str(s.get('port')) for s in asset.get('services', []))}"
            ),
        })

    # ── Edges: AD + DB ───────────────────────────────────────────────────────
    for a in assets:
        for b in assets:
            if a["ip"] == b["ip"]:
                continue

            if a["classification"] == "Domain Controller" and b["classification"] == "Windows Server":
                edge_ids += 1
                edges.append({
                    "id": f"e{edge_ids}", "from": a["ip"], "to": b["ip"],
                    "label": "AD", "dashes": True, "color": {"color": "#888"},
                })

            if a["classification"] == "Web Server":
                is_db_host = any(
                    int(svc["port"]) in db_ports
                    for svc in b.get("services", [])
                    if str(svc.get("port", "")).isdigit()
                )
                if is_db_host:
                    edge_ids += 1
                    edges.append({
                        "id": f"e{edge_ids}", "from": a["ip"], "to": b["ip"],
                        "label": "DB", "color": {"color": "#00bcd4"},
                    })

    # ── Traceroute nodes/edges ────────────────────────────────────────────────
    known_node_ids = {n["id"] for n in nodes}

    def add_hop_node(ip_):
        if ip_ in known_node_ids:
            return
        known_node_ids.add(ip_)
        nodes.append({
            "id": ip_, "label": ip_, "group": "PATH", "color": "#b0bec5",
            "type": "Router / Hop", "risk": 0, "services": [],
            "title": f"Traceroute hop: {ip_}",
        })

    for a in assets:
        path = a.get("trace_path")
        if not path or len(path) < 2:
            continue
        for hop_ip in path[:-1]:
            add_hop_node(hop_ip)
        for i in range(len(path) - 1):
            edge_ids += 1
            edges.append({
                "id": f"e{edge_ids}", "from": path[i], "to": path[i + 1],
                "label": "TR", "dashes": True, "color": {"color": "#9aa0a6"},
                "traceroute": True, "hidden": True,
            })

    trace_paths = {
        a["ip"]: a.get("trace_path")
        for a in assets if a.get("trace_path")
    }

    # ── Protocol-level edges ─────────────────────────────────────────────────
    def has_port(asset, port):
        return any(
            int(s.get("port", -1)) == port
            for s in asset.get("services", [])
            if str(s.get("port", "")).isdigit()
        )

    def add_edge(frm, to, label, color="#666", dashes=False):
        nonlocal edge_ids
        edge_ids += 1
        edges.append({
            "id": f"e{edge_ids}", "from": frm, "to": to,
            "label": label, "dashes": dashes, "color": {"color": color},
            "hidden": False,
        })

    dns_servers = [a for a in assets if has_port(a, 53)]
    web_servers = [a for a in assets if has_port(a, 80) or has_port(a, 443)]
    smb_servers = [a for a in assets if has_port(a, 445)]
    ssh_servers = [a for a in assets if has_port(a, 22)]
    rdp_servers = [a for a in assets if has_port(a, 3389)]
    clients     = [a for a in assets if a["classification"] in ("Workstation / Unknown", "Windows")]

    for c in clients:
        for d in dns_servers:
            add_edge(c["ip"], d["ip"], "DNS", color="#9c27b0", dashes=True)
        for w in web_servers:
            add_edge(c["ip"], w["ip"], "HTTP", color="#00bcd4", dashes=True)
        for s in smb_servers:
            add_edge(c["ip"], s["ip"], "SMB", color="#ffc107", dashes=True)

    for a in assets:
        for t in ssh_servers:
            if a["ip"] != t["ip"]:
                edge_ids += 1
                edges.append({
                    "id": f"e{edge_ids}", "from": a["ip"], "to": t["ip"],
                    "label": "SSH", "dashes": True, "color": {"color": "#4caf50"},
                    "admin": True, "hidden": True,
                })
        for t in rdp_servers:
            if a["ip"] != t["ip"]:
                edge_ids += 1
                edges.append({
                    "id": f"e{edge_ids}", "from": a["ip"], "to": t["ip"],
                    "label": "RDP", "dashes": True, "color": {"color": "#ff9800"},
                    "admin": True, "hidden": True,
                })

    # ── HTML template ─────────────────────────────────────────────────────────
    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Advanced SI Mapping</title>
<script src="../../../static/vis-network.min.js"></script>
<style>
body {{
  background: #0f111a;
  color: white;
  font-family: Arial;
  margin: 0;
}}
.wrapper {{
  display: grid;
  grid-template-columns: 320px 1fr;
  height: 100vh;
}}
.sidebar {{
  border-right: 1px solid #333;
  padding: 12px;
  overflow: auto;
  background: #0c0e16;
}}
#network {{
  width: 100%;
  height: 100vh;
  background: #1a1d2b;
}}
h2,h3 {{ margin: 8px 0; }}
.small {{ font-size: 12px; color: #bbb; }}
button {{
  background: #222;
  color: white;
  border: 1px solid #555;
  padding: 6px 10px;
  margin: 4px 4px 4px 0;
  cursor: pointer;
}}
select {{
  width: 100%;
  padding: 6px;
  background: #141828;
  color: white;
  border: 1px solid #444;
}}
.table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}}
.table td, .table th {{
  border-bottom: 1px solid #222;
  padding: 6px 4px;
}}
.badge {{
  display: inline-block;
  padding: 2px 6px;
  border: 1px solid #444;
  border-radius: 999px;
  font-size: 11px;
}}
.badge.critical {{ border-color:#ff4c4c; color:#ff4c4c; }}
.badge.high     {{ border-color:#ffae42; color:#ffae42; }}
.badge.medium   {{ border-color:#8bc34a; color:#8bc34a; }}
.badge.low      {{ border-color:#90a4ae; color:#90a4ae; }}
.vis-navigation .vis-button {{
  width: 52px !important; height: 52px !important;
  border-radius: 14px !important;
  background: linear-gradient(145deg, #1f2438, #151927) !important;
  border: 1px solid rgba(255,255,255,0.12) !important;
  box-shadow: 0 8px 25px rgba(0,0,0,0.5);
  display: flex !important; align-items: center; justify-content: center;
  transition: 0.2s ease;
}}
.vis-navigation .vis-button:hover {{ transform: translateY(-2px); box-shadow: 0 12px 35px rgba(0,0,0,0.6); }}
.vis-navigation .vis-up, .vis-navigation .vis-down,
.vis-navigation .vis-right, .vis-navigation .vis-left {{
  position: absolute !important; bottom: 25px !important; left: 82px !important;
}}
.vis-navigation .vis-zoomIn, .vis-navigation .vis-zoomOut, .vis-navigation .vis-zoomExtends {{
  position: absolute !important; bottom: 25px !important; right: 82px !important;
}}
.vis-navigation .vis-up      {{ bottom: 82px !important; }}
.vis-navigation .vis-left    {{ left: 25px !important; }}
.vis-navigation .vis-right   {{ left: 139px !important; }}
.vis-navigation .vis-zoomIn  {{ right: 139px !important; }}
.vis-navigation .vis-zoomExtends {{ right: 25px !important; }}
body.redteam #network  {{ background: #140b0b; }}
body.redteam .sidebar  {{ background: #0f0707; }}
body.redteam button    {{ border-color: rgba(255,76,76,0.4); }}
</style>
</head>
<body>
<div class="wrapper">
<div class="sidebar">
  <h2>SI Analytics</h2>

  <h3>Filters</h3>
  <h4>Nodes</h4>
  <button onclick="filterType('all')">All</button>
  <button onclick="filterType('Domain Controller')">DC</button>
  <button onclick="filterType('Windows Server')">Windows Server</button>
  <button onclick="filterType('Windows')">Windows</button>
  <button onclick="filterType('Web Server')">Web</button>
  <button onclick="filterType('Database Server')">DB</button>

  <h4>Link Filters</h4>
  <button onclick="toggleAllLinks()" id="allLinksBtn">Show All Links</button>
  <button onclick="toggleLink('TR')">TraceRoute</button>
  <button onclick="toggleLink('AD')">AD</button>
  <button onclick="toggleLink('DB')">DB</button>
  <button onclick="toggleLink('DNS')">DNS</button>
  <button onclick="toggleLink('HTTP')">HTTP</button>
  <button onclick="toggleLink('SMB')">SMB</button>
  <button onclick="toggleLink('SSH')">SSH</button>
  <button onclick="toggleLink('RDP')">RDP</button>

  <h4>Visuals</h4>
  <button onclick="toggleTeamMode()" id="teamBtn">Mode: Blue Team</button>
  <button onclick="toggleHeatmap()" id="heatToggleBtn">Heatmap: OFF</button>
  <button onclick="clusterZone('LAN')">Collapse LAN</button>
  <button onclick="clusterZone('DMZ / External')">Collapse DMZ</button>
  <button onclick="expandAllClusters()">Expand All</button>

  <h3>Attack</h3>
  <h4>Attack Simulation</h4>
  <select id="attackStart"></select>
  <button onclick="startAttackSim()">Start</button>
  <button onclick="stopAttackSim()">Stop</button>

  <h4>Traceroute</h4>
  <select id="traceTarget"></select>
  <button onclick="showTraceToTarget()">Show</button>
  <button onclick="hideAllTraceroutes()">Hide</button>

  <h4>Export</h4>
  <button onclick="exportPNG()">Export PNG</button>

  <h3>Exposure by zone</h3>
  <div class="small">Heuristic exposure score (services + risky ports + DMZ bonus)</div>
  <table class="table" id="exposureTable"></table>

  <h3>Criticality matrix</h3>
  <div>
    <span class="badge critical">critical: {criticality["critical"]}</span>
    <span class="badge high">high: {criticality["high"]}</span>
    <span class="badge medium">medium: {criticality["medium"]}</span>
    <span class="badge low">low: {criticality["low"]}</span>
  </div>

  <h3>Attack paths</h3>
  <div class="small">Simulated logical paths (not proven flows)</div>
  <select id="pathSelect" onchange="selectPath()"></select>
  <button onclick="clearPath()">Clear highlight</button>

  <h3>Top critical assets</h3>
  <table class="table" id="critTable"></table>
</div>

<div id="network"></div>
</div>

<script>
function svgDataUri(svg) {{
  return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
}}
const ICONS = {{
  windows: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
    <rect x="4" y="6" width="26" height="24" fill="#4FC3F7"/>
    <rect x="34" y="6" width="26" height="24" fill="#29B6F6"/>
    <rect x="4" y="34" width="26" height="24" fill="#29B6F6"/>
    <rect x="34" y="34" width="26" height="24" fill="#0288D1"/>
  </svg>`),
  linux: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
    <circle cx="32" cy="20" r="10" fill="#ECEFF1"/>
    <ellipse cx="32" cy="42" rx="16" ry="18" fill="#263238"/>
    <circle cx="28" cy="18" r="2" fill="#000"/>
    <circle cx="36" cy="18" r="2" fill="#000"/>
    <ellipse cx="32" cy="26" rx="5" ry="3" fill="#FFC107"/>
  </svg>`),
  router: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
    <rect x="10" y="26" width="44" height="22" rx="6" fill="#90A4AE"/>
    <circle cx="22" cy="37" r="3" fill="#00E676"/>
    <circle cx="32" cy="37" r="3" fill="#FFD600"/>
    <circle cx="42" cy="37" r="3" fill="#FF5252"/>
    <path d="M20 26 C22 14, 28 12, 32 10" stroke="#B0BEC5" stroke-width="3" fill="none"/>
    <path d="M44 26 C42 14, 36 12, 32 10" stroke="#B0BEC5" stroke-width="3" fill="none"/>
  </svg>`),
  web: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
    <rect x="10" y="10" width="44" height="44" rx="10" fill="#00BCD4"/>
    <path d="M18 30h28M18 38h28" stroke="#00323a" stroke-width="4"/>
    <circle cx="24" cy="24" r="3" fill="#00323a"/>
    <circle cx="32" cy="24" r="3" fill="#00323a"/>
    <circle cx="40" cy="24" r="3" fill="#00323a"/>
  </svg>`),
  unknown: svgDataUri(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
    <rect x="10" y="14" width="44" height="30" rx="6" fill="#78909C"/>
    <rect x="26" y="46" width="12" height="6" fill="#546E7A"/>
    <text x="32" y="36" font-size="22" text-anchor="middle" fill="#ECEFF1">?</text>
  </svg>`)
}};
function iconForType(t) {{
  if (t === "Windows" || t === "Windows Server") return ICONS.windows;
  if (t === "Linux Server") return ICONS.linux;
  if (t === "Router / Gateway") return ICONS.router;
  if (t === "Web Server") return ICONS.web;
  return ICONS.unknown;
}}

var allNodes = {json.dumps(nodes)};
allNodes = allNodes.map(n => {{
  n.shape = "image";
  n.image = iconForType(n.type);
  n.size = 28;
  n.borderWidth = 2;
  return n;
}});

var allEdges    = {json.dumps(edges)};
var exposure    = {json.dumps(exposure)};
var criticality = {json.dumps(criticality)};
var attackPaths = {json.dumps(attack_paths)};
var tracePaths  = {json.dumps(trace_paths)};

var container = document.getElementById('network');
var nodes = new vis.DataSet(allNodes);
var edges = new vis.DataSet(allEdges);
var data  = {{ nodes: nodes, edges: edges }};

var options = {{
  layout: {{ improvedLayout: true, randomSeed: 2 }},
  physics: {{
    enabled: true,
    solver: "forceAtlas2Based",
    forceAtlas2Based: {{
      gravitationalConstant: -50, centralGravity: 0.005,
      springLength: 100, springConstant: 0.04, damping: 0.9, avoidOverlap: 1,
    }},
    stabilization: {{ iterations: 1500 }},
  }},
  interaction: {{
    hover: true, dragNodes: true, dragView: true, zoomView: true,
    navigationButtons: true,
    keyboard: {{ enabled: true, speed: {{ x: 10, y: 10, zoom: 0.02 }}, bindToWindow: false }},
    zoomSpeed: 0.6,
  }},
  nodes: {{
    shape: "dot", size: 22,
    font: {{ color: "white", size: 14, strokeWidth: 3, strokeColor: "#000" }},
  }},
  edges: {{ smooth: {{ type: "dynamic" }}, width: 1.5 }},
  groups: {{
    "LAN":           {{ color: {{ background: "#1e88e5" }} }},
    "DMZ / External":{{ color: {{ background: "#e53935" }} }},
    "PATH":          {{ color: {{ background: "#607d8b" }} }},
  }},
}};

var network = new vis.Network(container, data, options);

edges.update(allEdges.filter(e => e.id).map(e => ({{ id: e.id, hidden: true }})));

network.on("afterDrawing", function() {{
  if (!network.canvas.body.container.style.cursor)
    network.canvas.body.container.style.cursor = "grab";
}});
network.on("hoverNode", function() {{
  network.canvas.body.container.style.cursor = "pointer";
}});
network.setOptions({{ interaction: {{ hover: true }} }});
network.once("stabilizationIterationsDone", function() {{
  network.setOptions({{ physics: false }});
}});

setTimeout(() => {{
  const map = {{
    "vis-up": "Up", "vis-down": "Down", "vis-left": "Left", "vis-right": "Right",
    "vis-zoomIn": "Zoom in", "vis-zoomOut": "Zoom out", "vis-zoomExtends": "Fit",
  }};
  Object.keys(map).forEach(cls => {{
    const el = document.querySelector("." + cls);
    if (el) el.title = map[cls];
  }});
}}, 200);

function injectNavIcons() {{
  const icons = {{
    "vis-up": "▲", "vis-down": "▼", "vis-left": "◀", "vis-right": "▶",
    "vis-zoomIn": "+", "vis-zoomOut": "−", "vis-zoomExtends": "⤢",
  }};
  Object.keys(icons).forEach(cls => {{
    const el = document.querySelector("." + cls);
    if (el) el.innerHTML = `<span style="font-size:20px;color:white;">${{icons[cls]}}</span>`;
  }});
}}
setTimeout(injectNavIcons, 400);

// ── Tables ──────────────────────────────────────────────────────────────────
function renderExposure() {{
  var html = "<tr><th>Zone</th><th>Hosts</th><th>Open</th><th>Risky</th><th>Avg</th></tr>";
  Object.keys(exposure).forEach(z => {{
    var v = exposure[z];
    html += `<tr><td>${{z}}</td><td>${{v.hosts}}</td><td>${{v.open_services_total}}</td><td>${{v.risky_ports_total}}</td><td>${{v.exposure_score_avg}}</td></tr>`;
  }});
  document.getElementById("exposureTable").innerHTML = html;
}}

function renderCriticalTop() {{
  var html = "<tr><th>IP</th><th>Type</th><th>Zone</th><th>Score</th><th>Lvl</th></tr>";
  criticality.items.slice(0, 10).forEach(it => {{
    html += `<tr><td>${{it.ip}}</td><td>${{it.classification}}</td><td>${{it.zone}}</td><td>${{it.criticality_score}}</td><td>${{it.criticality_level}}</td></tr>`;
  }});
  document.getElementById("critTable").innerHTML = html;
}}

function fillPathSelect() {{
  var sel = document.getElementById("pathSelect");
  sel.innerHTML = "";
  var idx = 0;
  attackPaths.forEach(sc => {{
    sc.paths.forEach(p => {{
      var opt = document.createElement("option");
      opt.value = idx;
      opt.textContent = sc.name + " | " + p.path.join(" -> ");
      opt.dataset.path    = JSON.stringify(p.path);
      opt.dataset.reasons = JSON.stringify(p.reasons);
      sel.appendChild(opt);
      idx++;
    }});
  }});
  if (sel.options.length === 0) {{
    var opt = document.createElement("option");
    opt.textContent = "No paths found";
    opt.value = "";
    sel.appendChild(opt);
  }}
}}

renderExposure();
renderCriticalTop();
fillPathSelect();

// ── Node filter ──────────────────────────────────────────────────────────────
var currentFilter = "all";
function filterType(type) {{
  currentFilter = type;
  var visibleNodeIds = new Set();
  var nodeUpdates = [];
  allNodes.forEach(n => {{
    var show = (type === "all") || (n.type === type);
    nodeUpdates.push({{ id: n.id, hidden: !show }});
    if (show) visibleNodeIds.add(n.id);
  }});
  nodes.update(nodeUpdates);
  var edgeUpdates = allEdges.map(e => ({{ id: e.id, hidden: !(visibleNodeIds.has(e.from) && visibleNodeIds.has(e.to)) }}));
  edges.update(edgeUpdates);
  setTimeout(() => network.fit({{ animation: {{ duration: 500, easingFunction: "easeInOutQuad" }} }}), 200);
}}

// ── Link toggles ─────────────────────────────────────────────────────────────
var allLinksVisible = false;
function toggleAllLinks() {{
  allLinksVisible = !allLinksVisible;
  edges.update(allEdges.filter(e => e.id).map(e => ({{ id: e.id, hidden: !allLinksVisible }})));
  document.getElementById("allLinksBtn").innerText = allLinksVisible ? "Hide All Links" : "Show All Links";
}}

function toggleLink(label) {{
  var currentlyVisible = false;
  allEdges.forEach(e => {{
    if (e.label === label) {{
      var cur = edges.get(e.id);
      if (cur && cur.hidden === false) currentlyVisible = true;
    }}
  }});
  var updates = allEdges.filter(e => e.label === label).map(e => ({{ id: e.id, hidden: currentlyVisible }}));
  edges.update(updates);
}}

// ── Team mode ────────────────────────────────────────────────────────────────
var redTeam = false;
function toggleTeamMode() {{
  redTeam = !redTeam;
  document.body.classList.toggle("redteam", redTeam);
  document.getElementById("teamBtn").innerText = redTeam ? "Mode: Red Team" : "Mode: Blue Team";
}}

// ── Heatmap ──────────────────────────────────────────────────────────────────
var heatmapOn = false;
var baseNodeColors = {{}};
allNodes.forEach(n => baseNodeColors[n.id] = n.color);

function riskColor(risk) {{
  if (risk >= 7) return "#ff4c4c";
  if (risk >= 4) return "#ffae42";
  return "#4caf50";
}}

function toggleHeatmap() {{
  heatmapOn = !heatmapOn;
  var updated = [];
  allNodes.forEach(n => {{
    var visible = (currentFilter === "all") || (n.type === currentFilter);
    if (!visible) return;
    updated.push({{ id: n.id, color: heatmapOn ? riskColor(n.risk || 0) : (baseNodeColors[n.id] || n.color) }});
  }});
  nodes.update(updated);
  document.getElementById("heatToggleBtn").innerText = heatmapOn ? "Heatmap: ON" : "Heatmap: OFF";
}}

// ── Cluster ──────────────────────────────────────────────────────────────────
var clustered = {{ "LAN": false, "DMZ / External": false }};
function clusterZone(zoneName) {{
  if (clustered[zoneName]) return;
  network.cluster({{
    joinCondition: n => n.group === zoneName,
    clusterNodeProperties: {{
      id: "cluster_" + zoneName,
      label: zoneName + " (cluster)",
      shape: "database",
      color: {{ background: "#111827", border: "#374151" }},
      font: {{ color: "white" }},
    }},
  }});
  clustered[zoneName] = true;
}}
function expandAllClusters() {{
  Object.keys(clustered).forEach(z => {{
    const cid = "cluster_" + z;
    if (network.isCluster(cid)) network.openCluster(cid);
    clustered[z] = false;
  }});
}}

// ── Attack simulation ────────────────────────────────────────────────────────
setTimeout(() => {{
  const sel = document.getElementById("attackStart");
  sel.innerHTML = "";
  allNodes.forEach(n => {{
    const o = document.createElement("option");
    o.value = n.id;
    o.textContent = n.id + " (" + n.type + ")";
    sel.appendChild(o);
  }});
}}, 100);

var attackTimers  = [];
var attackRunning = false;
var highlightedEdgeIds = [];

function stopAttackSim() {{
  attackRunning = false;
  attackTimers.forEach(t => clearTimeout(t));
  attackTimers = [];
  clearPath();
}}

function startAttackSim() {{
  stopAttackSim();
  attackRunning = true;
  const start = document.getElementById("attackStart").value;
  if (!start) return;
  const visibleNodes = new Set();
  allNodes.forEach(n => {{ if ((currentFilter === "all") || (n.type === currentFilter)) visibleNodes.add(n.id); }});
  if (!visibleNodes.has(start)) {{ alert("Selected node is not visible in current filter."); return; }}
  const adj = {{}};
  allEdges.forEach(e => {{
    if (visibleNodes.has(e.from) && visibleNodes.has(e.to) && !e.hidden) {{
      adj[e.from] = adj[e.from] || [];
      adj[e.to]   = adj[e.to]   || [];
      adj[e.from].push({{ n: e.to,   id: e.id }});
      adj[e.to].push({{   n: e.from, id: e.id }});
    }}
  }});
  const visited = new Set([start]);
  const q = [{{ node: start, depth: 0 }}];
  const stepDelay = 450;
  function highlightNode(id) {{ nodes.update({{ id, borderWidth: 4, color: "#ff4c4c" }}); }}
  function highlightEdge(eid) {{
    edges.update({{ id: eid, color: {{ color: "#ff4c4c" }}, width: 4, dashes: false }});
    highlightedEdgeIds.push(eid);
  }}
  let step = 0;
  while (q.length) {{
    const cur  = q.shift();
    const neigh = adj[cur.node] || [];
    neigh.forEach(x => {{
      if (visited.has(x.n)) return;
      visited.add(x.n);
      q.push({{ node: x.n, depth: cur.depth + 1 }});
      const t = setTimeout(() => {{
        if (!attackRunning) return;
        highlightEdge(x.id);
        highlightNode(x.n);
      }}, step * stepDelay);
      attackTimers.push(t);
      step++;
    }});
  }}
  network.focus(start, {{ scale: 1.25 }});
  highlightNode(start);
}}

// ── Traceroute ───────────────────────────────────────────────────────────────
setTimeout(() => {{
  const sel = document.getElementById("traceTarget");
  sel.innerHTML = "";
  allNodes.filter(n => n.type !== "Router / Hop").forEach(n => {{
    const o = document.createElement("option");
    o.value = n.id;
    o.textContent = n.id + " (" + n.type + ")";
    sel.appendChild(o);
  }});
}}, 120);

function hideAllTraceroutes() {{
  edges.update(allEdges.filter(e => e.label === "TR").map(e => ({{ id: e.id, hidden: true }})));
}}

function showTraceToTarget() {{
  const target = document.getElementById("traceTarget").value;
  if (!target) return;
  hideAllTraceroutes();
  const path = tracePaths[target];
  if (!path || path.length < 2) {{ alert("No traceroute path for this target."); return; }}
  const pairs = new Set();
  for (let i = 0; i < path.length - 1; i++) {{
    pairs.add(path[i] + "->" + path[i + 1]);
    pairs.add(path[i + 1] + "->" + path[i]);
  }}
  const updates = [];
  allEdges.forEach(e => {{
    if (e.label !== "TR") return;
    if (pairs.has(e.from + "->" + e.to)) {{
      updates.push({{ id: e.id, hidden: false, width: 3, dashes: false, color: {{ color: "#ff9800" }} }});
    }}
  }});
  edges.update(updates);
  network.focus(target, {{ scale: 1.2 }});
}}

// ── Export PNG ───────────────────────────────────────────────────────────────
function exportPNG() {{
  const visibleNodes = new Set();
  allNodes.forEach(n => {{ if ((currentFilter === "all") || (n.type === currentFilter)) visibleNodes.add(n.id); }});
  const nodeBackup = allNodes.map(n => ({{ id: n.id, hidden: nodes.get(n.id).hidden }}));
  const edgeBackup = allEdges.map(e => ({{ id: e.id, hidden: edges.get(e.id).hidden }}));
  nodes.update(allNodes.map(n => ({{ id: n.id, hidden: !visibleNodes.has(n.id) }})));
  edges.update(allEdges.map(e => ({{ id: e.id, hidden: !(visibleNodes.has(e.from) && visibleNodes.has(e.to)) }})));
  network.fit();
  setTimeout(() => {{
    var canvas = document.querySelector("canvas");
    var link = document.createElement("a");
    link.href = canvas.toDataURL("image/png");
    link.download = "si_mapping_filtered.png";
    link.click();
    nodes.update(nodeBackup);
    edges.update(edgeBackup);
    network.fit();
  }}, 400);
}}

// ── Attack path highlighting ─────────────────────────────────────────────────
function clearPath() {{
  highlightedEdgeIds.forEach(eid => {{
    edges.update({{ id: eid, color: {{ color: "#888" }}, width: 1, dashes: false }});
  }});
  highlightedEdgeIds = [];
}}

function selectPath() {{
  clearPath();
  var sel = document.getElementById("pathSelect");
  if (!sel.value) return;
  var opt  = sel.options[sel.selectedIndex];
  var path = JSON.parse(opt.dataset.path);
  for (var i = 0; i < path.length - 1; i++) {{
    var u = path[i], v = path[i + 1];
    allEdges.forEach(e => {{
      if ((e.from === u && e.to === v) || (e.from === v && e.to === u)) {{
        highlightedEdgeIds.push(e.id);
        edges.update({{ id: e.id, color: {{ color: "#ff4c4c" }}, width: 4, dashes: false }});
      }}
    }});
  }}
  network.focus(path[0], {{ scale: 1.2 }});
}}
</script>
</body>
</html>
"""

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    console.print(f"[green][+] Interactive topology map: {html_file}[/green]")
