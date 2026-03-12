# AutoRecon

⚡ **Automated reconnaissance & lightweight pentest audit tool**

AutoRecon is an interactive reconnaissance framework designed to perform fast infrastructure analysis, service fingerprinting and CVE correlation.

The tool provides an automated pipeline combining network scanning, web probing, vulnerability lookup and reporting.

---

# 🔎 Features

AutoRecon includes:

- IP / Domain / CIDR target support
- Subdomain enumeration
- Service detection (Nmap)
- HTTP probing
- CMS / technology detection
- WAF detection
- TLS auditing
- Web crawling
- CVE lookup (NVD API)
- Risk scoring
- JSON & PDF reporting
- Plugin system
- Interactive CLI console
- Results browser

---

# 🚀 Installation

## Linux/MacOs

```bash
curl -fsSL https://raw.githubusercontent.com/R3coNYT/AutoRecon/main/AutoRecon.sh | bash
```

## Windows

```bash
powershell -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/R3coNYT/AutoRecon/main/install.ps1 -UseBasicParsing | iex"
```

# ▶️ Run the Tool

## Linux/MacOs
```bash
Autorecon
```

## Windows
```bash
C:\Tools\AutoRecon\AutoRecon.bat
```

This will launch the interactive AutoRecon console.

---

# 🖥 AutoRecon Console

When launched, AutoRecon displays a console menu:

```
Recon on a target
Recon Results
Plugins
Exit
```

---

# 🎯 Recon on a Target

When selecting **Recon on a target**, the tool will:

- Ask you to choose or create a **client folder**
- Let you select an existing target or add a new one
- Ask for the target:

```
IP
Domain
CIDR network (example: 192.168.1.0/24)
```

Example:

```
example.com
192.168.1.10
10.0.0.0/24
```

Then AutoRecon asks whether to perform:

```
Full Nmap scan (all ports)
```

If enabled, it will run:

```
nmap -p- ...
```

Otherwise it performs a faster standard scan.

The scan pipeline is then launched automatically.

---

# 🔬 Recon Pipeline

For each discovered host / subdomain, AutoRecon performs the following analysis:

## Target processing

- IP / domain validation
- Reverse DNS lookup (if IP)
- Subdomain enumeration

---

## Network Analysis

### Host discovery

Identify reachable hosts.

### Nmap scan

- Open ports detection
- Service detection
- Version fingerprinting
- HTTP / HTTPS inference

---

## Web Analysis

If a web service is detected:

### HTTP probing

- Headers analysis
- HTML snippet analysis
- Web technology hints

### CMS detection

Detect technologies such as:

- WordPress
- Joomla
- common web frameworks

### WAF detection

Heuristic detection based on:

- HTTP headers
- response behavior

### TLS audit

If HTTPS is detected:

- TLS protocol version
- certificate information

---

## Web Crawling

Optional crawling allows:

- page discovery
- login form detection
- application surface analysis

---

## Vulnerability Detection

### CVE lookup

AutoRecon queries the **NVD API** using:

- detected services
- software versions
- web technologies

The tool then attempts to verify if detected versions are affected.

---

# 📊 Risk Scoring

Each analyzed host receives a risk score based on:

- exposed services
- discovered vulnerabilities
- TLS configuration
- web application exposure
- login form detection

Risk levels:

| Level | Meaning |
|------|------|
| 🔴 HIGH | Critical exposure |
| 🟡 MEDIUM | Moderate risk |
| 🟢 LOW | Limited risk |
| 🟣 POTENTIAL | Possible issues |

---

# 📁 Results

Results are stored inside:

```
results/
```

AutoRecon organizes scans by:

```
results/
 ├── client_name/
 │   ├── target_name/
 │   │   ├── report.json
 │   │   ├── report.pdf
 │   │   ├── nmap_*.txt
 │   │   └── scan data
```

Reports generated:

- JSON report → full structured data
- PDF report → pentest-style report

---

# 📂 Recon Results Browser

From the main menu you can select:

```
Recon Results
```

This allows you to:

- browse previous scans
- open report folders
- review past recon data

---

# 🔌 Plugin System

AutoRecon includes a plugin architecture located in:

```
plugins/
```

Each plugin contains:

```
plugin_name/
 ├── manifest.json
 └── plugin_script.py
```

Plugins can be launched from the **Plugins menu** in the console.

Example included plugins:

- mapping → network visualization
- ping → host reachability testing

---

# 🧠 Architecture Overview

```
User
 │
 ▼
AutoRecon Console
 │
 ├── Recon Engine
 │     ├── Host discovery
 │     ├── Nmap scanning
 │     ├── HTTP probing
 │     ├── CMS detection
 │     ├── WAF detection
 │     ├── TLS auditing
 │     ├── Crawling
 │     └── CVE lookup
 │
 ├── Reporting
 │     ├── JSON report
 │     └── PDF report
 │
 └── Plugin System
```

---

# ⚙️ Technologies Used

- Python
- Nmap
- Sublist3r
- NVD API
- Rich (CLI interface)
- Questionary (interactive prompts)

---



# 🚀 Uninstall

## Linux

```bash
sudo rm -f /usr/local/bin/AutoRecon
sudo rm -f /usr/local/bin/httpx
sudo rm -f /usr/local/bin/nuclei
sudo rm -rf /opt/autorecon
rm -rf ~/nuclei-templates
```

## MacOs

```bash
rm -f ~/.local/bin/AutoRecon
rm -f ~/.local/bin/httpx
rm -f ~/.local/bin/nuclei
rm -rf ~/Tools/AutoRecon
rm -rf ~/nuclei-templates
```

## Windows

```bash
Remove-Item "C:\Tools\AutoRecon" -Recurse -Force
Remove-Item "C:\Tools\bin\httpx.exe" -Force
Remove-Item "C:\Tools\bin\nuclei.exe" -Force
```

---
# 🔐 Disclaimer

This tool is intended for:

- Authorized penetration testing
- Security audits
- Educational purposes
- Red team training labs

⚠️ **Do not use this tool against systems without proper authorization.**
