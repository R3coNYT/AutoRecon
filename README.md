# AutoRecon

⚡ **Automated reconnaissance & lightweight pentest audit tool**

Built for fast infrastructure analysis, service fingerprinting and CVE correlation.

## AutoRecon includes

- IP & Domain support
- Subdomain enumeration
- Service detection
- CVE lookup (NVD)
- Risk scoring
- JSON & PDF reporting

---

# 🚀 Installation

## Clone the repository

```bash
git clone https://github.com/yourusername/AutoRecon.git
cd AutoRecon
```

## Install required system packages

```bash
sudo apt update && sudo apt upgrade
sudo apt install -y nmap python3 python3-venv python3-pip
```

## Create a Python virtual environment

```bash
python3 -m venv autorecon_env
```

## Activate the environment

```bash
source autorecon_env/bin/activate
```

## Install Python dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Run the Tool

## Start AutoRecon

```bash
python3 AutoRecon.py
```

## If the environment is not active

```bash
cd AutoRecon
source autorecon_env/bin/activate
python3 AutoRecon.py
```

---

# 🔎 How It Works

The tool performs a **full reconnaissance pipeline** on a given target (IP or domain).

---

# 1️⃣ Target Detection

You provide:

```bash
python main.py --target example.com
```

or

```bash
python main.py --target 1.2.3.4
```

The tool automatically detects whether the input is:

- An **IP address**
- A **Domain name**

---

# 2️⃣ Reverse DNS (If IP)

If the target is an IP:

- Reverse DNS lookup is performed
- If a domain is found → subdomain enumeration is launched
- If not → direct scan of the IP

---

# 3️⃣ Subdomain Enumeration

For domains (or reversed IP domains), the tool uses:

- **Sublist3r**

All discovered subdomains are added to the scan scope.

---

# 4️⃣ Per-Subdomain Deep Analysis

Each subdomain is analyzed **in parallel (multi-threaded)**.

For each target:

## 🔹 IP Resolution & Enrichment

- DNS resolution
- Reverse DNS
- RDAP lookup
- GeoIP enrichment

## 🔹 Nmap Scan

- Service detection
- Version detection
- Open ports discovery
- Protocol inference (HTTP / HTTPS)

## 🔹 HTTP Probe

If a web service is detected:

- Header analysis
- HTML snippet inspection
- Final URL resolution

## 🔹 CMS / Technology Detection

The tool attempts to detect:

- CMS (WordPress, Joomla, etc.)
- Web technologies
- Backend hints

## 🔹 WAF Detection

Heuristic-based detection using:

- HTTP headers
- Response fingerprints

## 🔹 TLS Audit (if HTTPS)

If HTTPS is detected:

- TLS protocol version
- Certificate information

## 🔹 Web Crawling (Optional)

If enabled:

- Recursive crawling
- Depth control
- Page limit
- Login form detection

## 🔹 CVE Lookup (NVD API)

If enabled:

The tool extracts:

- Service names
- Versions
- CMS technologies
- HTTP headers

Then:

- Queries the **NVD API**
- Matches potential vulnerabilities
- Verifies affected versions
- Flags confirmed vulnerabilities

---

# 📊 Risk Scoring System

Each subdomain receives a risk score based on:

- Open ports exposure
- Critical services detected
- TLS weaknesses
- WAF presence
- CVEs discovered
- Login form exposure

Final classification:

- 🔴 **HIGH**
- 🟡 **MEDIUM**
- 🟢 **LOW**
- 🟣 **POTENTIAL**

---

# 📁 Output

Each scan generates a timestamped folder:

```
results/<target>_<timestamp>/
```

Contains:

- `report.json` → Full structured data
- `report.pdf` → Executive pentest-style report
- `nmap_<sub>.txt` → Raw Nmap output
- `sublist3r/` → Subdomain enumeration results

---

# ⚙️ Features

- Multi-threaded scanning
- Live CVE counter
- Colored CLI output
- Structured JSON reporting
- Professional PDF export
- Modular architecture
- Plugin support

---

# 🧠 Architecture Overview

```
Target
   │
   ├── Reverse DNS (if IP)
   ├── Sublist3r
   │
   ├── For each subdomain:
   │     ├── DNS Resolution
   │     ├── IP Enrichment
   │     ├── Nmap Scan
   │     ├── HTTP Probe
   │     ├── CMS Detection
   │     ├── WAF Detection
   │     ├── TLS Audit
   │     ├── Crawl (optional)
   │     ├── CVE Lookup (optional)
   │     └── Risk Score
   │
   └── JSON + PDF Report
```

---

# 🛠 Command Options Example

```
--target example.com
--threads 10
--crawl-depth 2
--max-pages 50
--timeout 5
--use_nvd
--crawl
--pdf
--json
```

---

# 🔐 Disclaimer

This tool is intended for:

- Authorized penetration testing
- Security audits
- Educational purposes
- Red team training labs

⚠️ **Do not use this tool without proper authorization.**
