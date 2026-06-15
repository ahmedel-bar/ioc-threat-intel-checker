# IOC Checker — SOC Threat Intelligence CLI Tool

A production-grade **Indicator of Compromise (IOC) checker** built for
SOC analysts and Cyber Threat Intelligence (CTI) practitioners.

---

## Project Structure

```
ioc_checker/
├── ioc_checker.py      # Main tool — all classes and CLI logic
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## Features

| Capability                    | Details                                              |
|-------------------------------|------------------------------------------------------|
| IOC Types                     | IP, Domain, URL, MD5, SHA1, SHA256                   |
| File Scanning                 | Auto-computes MD5 / SHA1 / SHA256 for local files    |
| Threat Intel Providers        | VirusTotal, AbuseIPDB, OTX, Hybrid Analysis, CAPE, MalShare |
| Concurrent Queries            | ThreadPoolExecutor — all providers queried in parallel |
| Colored Output                | Red = Malicious · Yellow = Suspicious · Green = Clean |
| Rich Tables                   | SOC-style result tables and summary panels           |
| Error Handling                | Rate limits, timeouts, missing keys, bad formats     |

---

## Installation

```bash
# 1. Clone / download the files
git clone https://github.com/yourname/ioc-checker.git
cd ioc-checker

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
.venv\Scripts\activate             # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## API Key Setup

Export your API keys as environment variables before running the tool.

```bash
# Linux / macOS
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export OTX_API_KEY="your_otx_key"
export HYBRID_ANALYSIS_API_KEY="your_hybrid_analysis_key"
export MALSHARE_API_KEY="your_malshare_key"

# Windows (PowerShell)
$env:VT_API_KEY = "your_virustotal_key"
$env:ABUSEIPDB_API_KEY = "your_abuseipdb_key"
$env:OTX_API_KEY = "your_otx_key"
$env:HYBRID_ANALYSIS_API_KEY = "your_hybrid_analysis_key"
$env:MALSHARE_API_KEY = "your_malshare_key"
```

Free API keys:
- **VirusTotal** → https://www.virustotal.com/gui/join-us
- **AbuseIPDB** → https://www.abuseipdb.com/register
- **AlienVault OTX** → https://otx.alienvault.com/accounts/signup
- **Hybrid Analysis** → https://www.hybrid-analysis.com/signup
- **MalShare** → https://malshare.com/register.php
- **CAPE Sandbox** → https://capesandbox.com (no key needed)

---

## Usage

```bash
# Check a single IP address
python ioc_checker.py --ip 8.8.8.8

# Check a domain
python ioc_checker.py --domain malware.example.com

# Check a URL
python ioc_checker.py --url http://malicious.site/payload.exe

# Check a file hash (MD5 / SHA1 / SHA256)
python ioc_checker.py --hash d41d8cd98f00b204e9800998ecf8427e

# Scan a local file (auto-computes all hashes → SHA256 lookup)
python ioc_checker.py -f /samples/malware.exe
python ioc_checker.py --file suspicious.pdf

# Combine multiple IOC types in a single run
python ioc_checker.py --ip 1.2.3.4 8.8.8.8 --url http://bad.com --hash abc123...

# Show help
python ioc_checker.py --help

# Show version
python ioc_checker.py --version
```

---

## Example Output

```
┌──────────────────────────────────────────────────────────────────────┐
│ ◈ Scanning IOC                                                        │
│   IOC  : d41d8cd98f00b204e9800998ecf8427e9800998ecf8427e...          │
│   Type : SHA256                                                       │
└──────────────────────────────────────────────────────────────────────┘

╔══════════════ Results for <hash> (SHA256) ═══════════════════════╗
║ Provider            │ Field            │ Value          │ Verdict  ║
╠═════════════════════╪══════════════════╪════════════════╪══════════╣
║ VirusTotal          │ Detection Ratio  │ 58 / 72        │ MALICIOUS║
║ AlienVault OTX      │ Pulses/Families  │ Pulses: 14 ... │ MALICIOUS║
║ Hybrid Analysis     │ Threat Score     │ 95/100 ...     │ MALICIOUS║
║ CAPE Sandbox        │ Detections       │ Task: 12345    │ MALICIOUS║
║ MalShare            │ Repository       │ Found | PE32   │ MALICIOUS║
╚══════════════════════════════════════════════════════════════════╝

┌─────────────── ◈ IOC SUMMARY ────────────────┐
│  IOC          : d41d8cd9...                   │
│  Type         : SHA256                        │
│  Overall      : MALICIOUS                     │
│  ─────────────────────────────────            │
│  VirusTotal        : MALICIOUS                │
│  AlienVault OTX    : MALICIOUS                │
│  Hybrid Analysis   : MALICIOUS                │
│  CAPE Sandbox      : MALICIOUS                │
│  MalShare          : MALICIOUS                │
└───────────────────────────────────────────────┘
```

---

## Class Architecture

```
IOCChecker              — Orchestrator: loads keys, dispatches tasks, renders output
├── VirusTotalClient    — VT API v3: IP, Domain, URL, Hash
├── AbuseIPDBClient     — IP confidence score & report count
├── OTXClient           — Pulse count & malware families
├── HybridAnalysisClient— Sandbox verdict & threat score
├── CAPESandboxClient   — CAPE public sandbox (no key required)
└── MalShareClient      — Malware repository hash lookup
```

---

## Provider Coverage Matrix

| Provider        | IP | Domain | URL | Hash |
|-----------------|----|--------|-----|------|
| VirusTotal      | ✔  | ✔      | ✔   | ✔    |
| AbuseIPDB       | ✔  | ✗      | ✗   | ✗    |
| AlienVault OTX  | ✔  | ✔      | ✔   | ✔    |
| Hybrid Analysis | ✗  | ✗      | ✗   | ✔    |
| CAPE Sandbox    | ✗  | ✗      | ✗   | ✔    |
| MalShare        | ✗  | ✗      | ✗   | ✔    |

---

## Error Handling

The tool gracefully handles:
- `Missing API keys` — shows ✘ in the API key status table; skips that provider
- `Rate limiting` — returns "Rate limit exceeded" in the result row
- `Timeouts` — configurable via `REQUEST_TIMEOUT` constant (default 15s)
- `Network errors` — connection errors reported per-provider, tool continues
- `Invalid IOC format` — auto-detection warns and skips malformed values
- `File not found` — clear error message with the bad path
- `Unexpected API responses` — safe parse with fallback error messages

---

## License

MIT — free for personal and commercial use.
