# Pentest

## ⚡ Automated reconnaissance & lightweight pentest audit tool
Built for fast infrastructure analysis, service fingerprinting and CVE correlation.

## ⚠️ Version Notice
## ✅ Use V2

The V1 version is deprecated and not fully functional.

V2 is stable and includes:
  - IP & Domain support
  - Subdomain enumeration
  - Service detection
  - CVE lookup (NVD)
  - Risk scoring

JSON & PDF reporting

🔎 How It Works

The tool performs a full reconnaissance pipeline on a given target (IP or domain).

1️⃣ Target Detection

You provide:

python main.py --target example.com

or

python main.py --target 1.2.3.4

The tool automatically detects whether the input is:

An IP address

A Domain name

2️⃣ Reverse DNS (If IP)

If the target is an IP:

It performs a reverse DNS lookup

If a domain is found → subdomain enumeration is launched

If not → direct scan of the IP

3️⃣ Subdomain Enumeration

For domains (or reversed IP domains), the tool uses:

Sublist3r

All discovered subdomains are added to the scan scope.

4️⃣ Per-Subdomain Deep Analysis

Each subdomain is analyzed in parallel (multi-threaded).

For each target:

🔹 IP Resolution & Enrichment

DNS resolution

Reverse DNS

RDAP lookup

GeoIP enrichment

🔹 Nmap Scan

Service detection

Version detection

Open ports discovery

Protocol inference (HTTP/HTTPS)

🔹 HTTP Probe

If a web service is detected:

Header analysis

HTML snippet inspection

Final URL resolution

🔹 CMS / Technology Detection

The tool attempts to detect:

CMS (WordPress, Joomla, etc.)

Web technologies

Backend hints

🔹 WAF Detection

Heuristic-based WAF detection using:

HTTP headers

Response patterns

🔹 TLS Audit (if HTTPS)

If HTTPS is detected:

TLS protocol version

Certificate details

🔹 Web Crawling (Optional)

If enabled:

Recursive crawl

Depth control

Page limit

Login form detection

🔹 CVE Lookup (NVD API)

If enabled:

The tool extracts:

Service names

Versions (cleaned)

CMS technologies

Server headers

Then:

Queries NVD

Matches CVEs

Verifies affected versions

Flags confirmed vulnerabilities

📊 Risk Scoring System

Each subdomain receives a risk score based on:

Open ports exposure

Critical services detected

TLS weaknesses

WAF presence

CVEs discovered

Login form exposure

Final classification:

🔴 HIGH

🟡 MEDIUM

🟢 LOW

🟣 POTENTIAL

📁 Output

Each run generates a timestamped folder:

results/<target>_<timestamp>/

Contains:

report.json → Full structured data

report.pdf → Executive pentest-style report

nmap_<sub>.txt → Raw Nmap output per target

Sublist3r output folder

⚙️ Features

Multi-threaded scanning

Live CVE counter

Colored CLI output

Structured JSON reporting

Professional PDF export

Modular architecture

🧠 Architecture Overview
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
🛠 Command Options (Example)
--target example.com
--threads 10
--crawl-depth 2
--max-pages 50
--timeout 5
--use-nvd
--crawl
--pdf
--json
🔐 Disclaimer

This tool is intended for:

Authorized penetration testing

Security audits

Educational purposes

Red team training labs

⚠️ Do not use without proper authorization.
