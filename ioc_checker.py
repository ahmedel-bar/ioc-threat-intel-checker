#!/usr/bin/env python3
"""
=============================================================================
IOC Checker - Threat Intelligence CLI Tool
=============================================================================
Author      : Senior Python Security Engineer
Description : A production-grade Indicator of Compromise (IOC) checker that
              queries multiple threat intelligence platforms concurrently.
              Supports IPs, domains, URLs, file hashes, and local file scanning.

Supported Platforms:
    - VirusTotal API v3
    - AbuseIPDB API
    - AlienVault OTX API
    - Hybrid Analysis API
    - CAPE Sandbox API
    - MalShare API

Usage:
    python ioc_checker.py --ip 8.8.8.8
    python ioc_checker.py --domain example.com
    python ioc_checker.py --url http://example.com
    python ioc_checker.py --hash <md5|sha1|sha256>
    python ioc_checker.py -f malware.exe
    python ioc_checker.py --ip 1.1.1.1 --url example.com --hash <hash>

Environment Variables:
    VT_API_KEY              VirusTotal API key
    ABUSEIPDB_API_KEY       AbuseIPDB API key
    OTX_API_KEY             AlienVault OTX API key
    HYBRID_ANALYSIS_API_KEY Hybrid Analysis API key
    MALSHARE_API_KEY        MalShare API key
=============================================================================
"""

import os
import re
import sys
import hashlib
import argparse
import ipaddress
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.rule import Rule

# ─────────────────────────────────────────────────────────────────────────────
# Global console instance (Rich library)
# ─────────────────────────────────────────────────────────────────────────────
console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
REQUEST_TIMEOUT = 30          # seconds per API call
MAX_WORKERS     = 6           # concurrent threads for API queries
TOOL_VERSION    = "1.0.0"
TOOL_NAME       = "IOC Checker"


# =============================================================================
# Utility Functions
# =============================================================================

def detect_ioc_type(ioc: str) -> str:
    """
    Auto-detect the type of an IOC string.

    Returns one of: 'ip', 'domain', 'url', 'md5', 'sha1', 'sha256', 'unknown'
    """
    ioc = ioc.strip()

    # URL — must contain a scheme
    if re.match(r'^https?://', ioc, re.IGNORECASE):
        return 'url'

    # IPv4 address
    try:
        ipaddress.IPv4Address(ioc)
        return 'ip'
    except ValueError:
        pass

    # IPv6 address
    try:
        ipaddress.IPv6Address(ioc)
        return 'ip'
    except ValueError:
        pass

    # Hash detection by length (hex chars only)
    if re.fullmatch(r'[0-9a-fA-F]+', ioc):
        if len(ioc) == 32:
            return 'md5'
        elif len(ioc) == 40:
            return 'sha1'
        elif len(ioc) == 64:
            return 'sha256'

    # Domain (basic validation)
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', ioc):
        return 'domain'

    return 'unknown'


def compute_file_hashes(file_path: str) -> dict:
    """
    Compute MD5, SHA1, and SHA256 hashes for a local file.

    Args:
        file_path: Absolute or relative path to the file.

    Returns:
        dict with keys 'md5', 'sha1', 'sha256'

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If the file cannot be read.
    """
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            # Read in 64 KB chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(65536), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except IOError as e:
        raise IOError(f"Cannot read file '{file_path}': {e}")

    return {
        'md5':    md5.hexdigest(),
        'sha1':   sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
    }


def severity_color(label: str) -> str:
    """
    Map a verdict label to a Rich color tag.

    'malicious'  → red
    'suspicious' → yellow
    'clean'      → green
    anything else → white (no color)
    """
    label_lower = label.lower()
    if any(x in label_lower for x in ['malicious', 'mal', 'infected', 'found', 'trojan', 'virus']):
        return 'red'
    elif any(x in label_lower for x in ['suspicious', 'unknown', 'undetected', 'no rating']):
        return 'yellow'
    elif any(x in label_lower for x in ['clean', 'safe', 'harmless', 'not found', 'benign']):
        return 'green'
    return 'white'


def colorize(text: str, verdict: str) -> Text:
    """Return a Rich Text object colored by verdict."""
    color = severity_color(verdict)
    return Text(text, style=color)


# =============================================================================
# API Client Classes
# =============================================================================

class VirusTotalClient:
    """
    VirusTotal API v3 client.

    Supports lookup for:
        - IP addresses  (/ip_addresses/{ip})
        - Domains       (/domains/{domain})
        - URLs          (/urls/{id})  — URL must be base64-encoded
        - File hashes   (/files/{hash})

    Docs: https://developers.virustotal.com/reference
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key} if api_key else {}

    def _get(self, endpoint: str) -> dict:
        """Perform a GET request; return parsed JSON or error dict."""
        if not self.api_key:
            return {"error": "VT_API_KEY not set"}
        url = f"{self.BASE_URL}{endpoint}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 429:
                return {"error": "Rate limit exceeded"}
            if resp.status_code == 404:
                return {"error": "IOC not found in VirusTotal"}
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            return {"error": "Request timed out"}
        except requests.exceptions.ConnectionError:
            return {"error": "Network connection error"}
        except requests.exceptions.HTTPError as e:
            return {"error": f"HTTP error: {e}"}

    def check_virustotal(self, ioc: str, ioc_type: str) -> dict:
        """
        Query VirusTotal for any IOC type.

        Returns a normalised result dict:
            {
              'source':      'VirusTotal',
              'detection':   '45 / 72',
              'verdict':     'malicious',
              'link':        'https://...',
              'error':       None  (or error message)
            }
        """
        result = {"source": "VirusTotal", "detection": "N/A",
                  "verdict": "unknown", "link": "N/A", "error": None}

        if ioc_type == 'ip':
            data = self._get(f"/ip_addresses/{ioc}")
        elif ioc_type == 'domain':
            data = self._get(f"/domains/{ioc}")
        elif ioc_type == 'url':
            # VT requires URL ID = base64url(url) without padding
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip('=')
            data = self._get(f"/urls/{url_id}")
        elif ioc_type in ('md5', 'sha1', 'sha256', 'hash'):
            data = self._get(f"/files/{ioc}")
        else:
            result["error"] = f"Unsupported IOC type: {ioc_type}"
            return result

        if "error" in data and "data" not in data:
            result["error"] = data["error"]
            return result

        try:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())
            result["detection"] = f"{malicious} / {total}"

            if malicious > 0:
                result["verdict"] = "malicious"
            elif suspicious > 0:
                result["verdict"] = "suspicious"
            else:
                result["verdict"] = "clean"

            # Build a human-readable VT link
            vt_id = data["data"].get("id", ioc)
            if ioc_type == 'ip':
                result["link"] = f"https://www.virustotal.com/gui/ip-address/{ioc}"
            elif ioc_type == 'domain':
                result["link"] = f"https://www.virustotal.com/gui/domain/{ioc}"
            elif ioc_type == 'url':
                result["link"] = f"https://www.virustotal.com/gui/url/{vt_id}"
            else:
                result["link"] = f"https://www.virustotal.com/gui/file/{ioc}"
        except (KeyError, TypeError) as e:
            result["error"] = f"Unexpected response format: {e}"

        return result


class AbuseIPDBClient:
    """
    AbuseIPDB API client (v2).

    Only applicable to IP addresses.
    Returns confidence score (0–100%) and usage type.

    Docs: https://docs.abuseipdb.com/
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        } if api_key else {}

    def check_abuseipdb(self, ip: str) -> dict:
        """
        Query AbuseIPDB confidence score for an IP address.

        Returns normalised result dict.
        """
        result = {"source": "AbuseIPDB", "confidence": "N/A",
                  "verdict": "unknown", "country": "N/A",
                  "usage_type": "N/A", "error": None}

        if not self.api_key:
            result["error"] = "ABUSEIPDB_API_KEY not set"
            return result

        try:
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
            resp = requests.get(
                f"{self.BASE_URL}/check",
                headers=self.headers,
                params=params,
                timeout=REQUEST_TIMEOUT
            )
            if resp.status_code == 429:
                result["error"] = "Rate limit exceeded"
                return result
            resp.raise_for_status()
            data = resp.json().get("data", {})

            score = data.get("abuseConfidenceScore", 0)
            result["confidence"]  = f"{score}%"
            result["country"]     = data.get("countryCode", "N/A")
            result["usage_type"]  = data.get("usageType", "N/A") or "N/A"
            result["total_reports"] = data.get("totalReports", 0)

            if score >= 75:
                result["verdict"] = "malicious"
            elif score >= 25:
                result["verdict"] = "suspicious"
            else:
                result["verdict"] = "clean"

        except requests.exceptions.Timeout:
            result["error"] = "Request timed out"
        except requests.exceptions.ConnectionError:
            result["error"] = "Network connection error"
        except requests.exceptions.HTTPError as e:
            result["error"] = f"HTTP error: {e}"
        except (KeyError, ValueError) as e:
            result["error"] = f"Response parse error: {e}"

        return result


class OTXClient:
    """
    AlienVault Open Threat Exchange (OTX) API client.

    Supports IP, domain, URL, and file hash indicators.
    Returns pulse count (community threat reports) and malware families.

    Docs: https://otx.alienvault.com/api
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
        self.headers = {"X-OTX-API-KEY": api_key} if api_key else {}

    def _get(self, endpoint: str) -> dict:
        if not self.api_key:
            return {"error": "OTX_API_KEY not set"}
        url = f"{self.BASE_URL}{endpoint}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 429:
                return {"error": "Rate limit exceeded"}
            if resp.status_code == 404:
                return {"error": "IOC not found in OTX"}
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            return {"error": "Request timed out"}
        except requests.exceptions.ConnectionError:
            return {"error": "Network connection error"}
        except requests.exceptions.HTTPError as e:
            return {"error": f"HTTP error: {e}"}

    def check_otx(self, ioc: str, ioc_type: str) -> dict:
        """
        Query OTX for pulse count and malware families.

        Returns normalised result dict.
        """
        result = {"source": "AlienVault OTX", "pulses": "N/A",
                  "malware_families": "N/A", "verdict": "unknown", "error": None}

        # Build the correct endpoint per IOC type
        if ioc_type == 'ip':
            endpoint = f"/indicators/IPv4/{ioc}/general"
        elif ioc_type == 'domain':
            endpoint = f"/indicators/domain/{ioc}/general"
        elif ioc_type == 'url':
            # OTX uses the hostname for URL lookups
            hostname = urlparse(ioc).hostname or ioc
            endpoint = f"/indicators/hostname/{hostname}/general"
        elif ioc_type in ('md5', 'sha1', 'sha256', 'hash'):
            endpoint = f"/indicators/file/{ioc}/general"
        else:
            result["error"] = f"Unsupported IOC type: {ioc_type}"
            return result

        data = self._get(endpoint)

        if "error" in data:
            result["error"] = data["error"]
            return result

        try:
            pulses = data.get("pulse_info", {}).get("count", 0)
            result["pulses"] = str(pulses)

            # Extract unique malware family names from pulse tags
            families = set()
            for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
                for tag in pulse.get("tags", []):
                    if len(tag) > 2:
                        families.add(tag.lower())
            result["malware_families"] = ", ".join(list(families)[:3]) if families else "None"

            if pulses >= 5:
                result["verdict"] = "malicious"
            elif pulses > 0:
                result["verdict"] = "suspicious"
            else:
                result["verdict"] = "clean"

        except (KeyError, TypeError) as e:
            result["error"] = f"Response parse error: {e}"

        return result


class HybridAnalysisClient:
    """
    Hybrid Analysis (Falcon Sandbox) API client.

    Supports file hash lookups to retrieve sandbox verdicts.
    Returns overall verdict, threat score, and malware family.

    Docs: https://www.hybrid-analysis.com/docs/api/v2
    """

    BASE_URL = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
        self.headers = {
            "api-key": api_key,
            "User-Agent": "Falcon Sandbox",
            "Content-Type": "application/x-www-form-urlencoded"
        } if api_key else {}

    def check_hybrid_analysis(self, ioc: str, ioc_type: str) -> dict:
        """
        Query Hybrid Analysis for sandbox verdict.

        Returns normalised result dict.
        """
        result = {"source": "Hybrid Analysis", "verdict": "unknown",
                  "threat_score": "N/A", "malware_family": "N/A",
                  "av_detect": "N/A", "error": None}

        if not self.api_key:
            result["error"] = "HYBRID_ANALYSIS_API_KEY not set"
            return result

        # Hybrid Analysis supports hash-based lookups only via this endpoint
        if ioc_type not in ('md5', 'sha1', 'sha256', 'hash'):
            result["error"] = "Hybrid Analysis only supports hash lookups"
            return result

        try:
            resp = requests.post(
                f"{self.BASE_URL}/search/hash",
                headers=self.headers,
                data={"hash": ioc},
                timeout=REQUEST_TIMEOUT
            )
            if resp.status_code == 429:
                result["error"] = "Rate limit exceeded"
                return result
            if resp.status_code == 401:
                result["error"] = "Invalid API key"
                return result
            resp.raise_for_status()
            data = resp.json()

            if not data:
                result["verdict"] = "not found"
                result["error"] = "Hash not found in Hybrid Analysis"
                return result

            # Take the most recent / highest-threat report
            report = data[0] if isinstance(data, list) else data
            verdict       = report.get("verdict", "unknown") or "unknown"
            threat_score  = report.get("threat_score")
            malware_family = report.get("vx_family", "N/A") or "N/A"
            av_detect     = report.get("av_detect", "N/A")

            result["verdict"]       = verdict.lower()
            result["threat_score"]  = str(threat_score) if threat_score is not None else "N/A"
            result["malware_family"] = malware_family
            result["av_detect"]     = f"{av_detect}%" if av_detect not in (None, "N/A") else "N/A"

        except requests.exceptions.Timeout:
            result["error"] = "Request timed out"
        except requests.exceptions.ConnectionError:
            result["error"] = "Network connection error"
        except requests.exceptions.HTTPError as e:
            result["error"] = f"HTTP error: {e}"
        except (KeyError, ValueError, IndexError) as e:
            result["error"] = f"Response parse error: {e}"

        return result


class CAPESandboxClient:
    """
    CAPE Sandbox public API client.

    CAPE is an open-source fork of Cuckoo Sandbox.
    Uses the public instance at https://capesandbox.com

    Supports SHA256 hash lookups against submitted samples.

    Docs: https://capesandbox.com/apiv2/
    """

    BASE_URL = "https://capesandbox.com/apiv2"

    def __init__(self):
        # CAPE public API requires no key for basic searches
        self.headers = {"User-Agent": f"IOC-Checker/{TOOL_VERSION}"}

    def check_cape(self, ioc: str, ioc_type: str) -> dict:
        """
        Query CAPE Sandbox for analysis reports by hash.

        Returns normalised result dict.
        """
        result = {"source": "CAPE Sandbox", "verdict": "unknown",
                  "detections": "N/A", "task_id": "N/A", "error": None}

        if ioc_type not in ('md5', 'sha1', 'sha256', 'hash'):
            result["error"] = "CAPE only supports hash lookups"
            return result

        try:
            # Search endpoint: POST with sha256 query
            resp = requests.get(
                f"{self.BASE_URL}/tasks/search/sha256/{ioc}/",
                headers=self.headers,
                timeout=REQUEST_TIMEOUT
            )
            if resp.status_code == 404:
                result["verdict"] = "not found"
                result["error"]   = "Hash not found in CAPE"
                return result
            if resp.status_code == 429:
                result["error"] = "Rate limit exceeded"
                return result
            resp.raise_for_status()
            data = resp.json()

            tasks = data.get("data", [])
            if not tasks:
                result["verdict"] = "not found"
                result["error"]   = "No CAPE reports for this hash"
                return result

            # Use the most recent task
            task      = tasks[0]
            task_id   = task.get("id", "N/A")
            detections = task.get("detections", "N/A") or "N/A"
            score     = task.get("malscore", 0) or 0

            result["task_id"]    = str(task_id)
            result["detections"] = str(detections)

            if score >= 7:
                result["verdict"] = "malicious"
            elif score >= 4:
                result["verdict"] = "suspicious"
            else:
                result["verdict"] = "clean"

        except requests.exceptions.Timeout:
            result["error"] = "Request timed out"
        except requests.exceptions.ConnectionError:
            result["error"] = "Network connection error (CAPE may be offline)"
        except requests.exceptions.HTTPError as e:
            result["error"] = f"HTTP error: {e}"
        except (KeyError, ValueError) as e:
            result["error"] = f"Response parse error: {e}"

        return result


class MalShareClient:
    """
    MalShare API client.

    MalShare is a free malware repository.
    Supports checking whether a file hash (MD5/SHA1/SHA256) exists in the repository.

    Docs: https://malshare.com/doc.php
    """

    BASE_URL = "https://malshare.com/api.php"

    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key

    def check_malshare(self, ioc: str, ioc_type: str) -> dict:
        """
        Query MalShare for presence of a file hash.

        Returns normalised result dict.
        """
        result = {"source": "MalShare", "found": "N/A",
                  "verdict": "unknown", "file_type": "N/A", "error": None}

        if not self.api_key:
            result["error"] = "MALSHARE_API_KEY not set"
            return result

        if ioc_type not in ('md5', 'sha1', 'sha256', 'hash'):
            result["error"] = "MalShare only supports hash lookups"
            return result

        try:
            params = {
                "api_key": self.api_key,
                "action":  "details",
                "hash":    ioc
            }
            resp = requests.get(
                self.BASE_URL,
                params=params,
                timeout=REQUEST_TIMEOUT
            )
            if resp.status_code == 429:
                result["error"] = "Rate limit exceeded"
                return result
            resp.raise_for_status()

            # MalShare returns an error string for unknown hashes
            text = resp.text.strip()
            if "Sample not found" in text or "ERROR" in text:
                result["found"]   = "Not Found"
                result["verdict"] = "clean"
                return result

            data = resp.json()
            result["found"]     = "Found"
            result["file_type"] = data.get("F_TYPE", "N/A") or "N/A"
            result["verdict"]   = "malicious"   # Presence in MalShare = malicious

        except requests.exceptions.Timeout:
            result["error"] = "Request timed out"
        except requests.exceptions.ConnectionError:
            result["error"] = "Network connection error"
        except requests.exceptions.HTTPError as e:
            result["error"] = f"HTTP error: {e}"
        except (KeyError, ValueError) as e:
            result["error"] = f"Response parse error: {e}"

        return result


# =============================================================================
# IOC Checker Orchestrator
# =============================================================================

class IOCChecker:
    """
    Main orchestrator for IOC threat intelligence lookups.

    Initialises all provider clients from environment variables,
    dispatches concurrent API calls, and renders Rich tables.
    """

    def __init__(self):
        # Load API keys from environment variables
        self.vt_key       = os.getenv("VT_API_KEY")
        self.abuse_key    = os.getenv("ABUSEIPDB_API_KEY")
        self.otx_key      = os.getenv("OTX_API_KEY")
        self.hybrid_key   = os.getenv("HYBRID_ANALYSIS_API_KEY")
        self.malshare_key = os.getenv("MALSHARE_API_KEY")

        # Instantiate all provider clients
        self.vt       = VirusTotalClient(self.vt_key)
        self.abuse    = AbuseIPDBClient(self.abuse_key)
        self.otx      = OTXClient(self.otx_key)
        self.hybrid   = HybridAnalysisClient(self.hybrid_key)
        self.cape     = CAPESandboxClient()
        self.malshare = MalShareClient(self.malshare_key)

    # ── Rendering helpers ─────────────────────────────────────────────────────

    def _print_banner(self):
        """Display the ASCII art tool banner."""
        banner = Text()
        banner.append("\n ██╗ ██████╗  ██████╗      ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ \n", style="bold red")
        banner.append(" ██║██╔═══██╗██╔════╝     ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗\n", style="bold red")
        banner.append(" ██║██║   ██║██║          ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝\n", style="bold yellow")
        banner.append(" ██║██║   ██║██║          ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗\n", style="bold yellow")
        banner.append(" ██║╚██████╔╝╚██████╗     ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║\n", style="bold green")
        banner.append(" ╚═╝ ╚═════╝  ╚═════╝      ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n", style="bold green")
        banner.append(f"  Threat Intelligence IOC Checker  v{TOOL_VERSION}  │  SOC & CTI Tool\n", style="dim cyan")
        console.print(banner)

    def _api_key_status_table(self):
        """Display a table showing which API keys are configured."""
        table = Table(title="API Key Status", box=box.SIMPLE_HEAVY,
                      title_style="bold cyan", show_header=True)
        table.add_column("Provider",    style="bold white", width=25)
        table.add_column("Status",      width=12)
        table.add_column("Env Variable", style="dim")

        providers = [
            ("VirusTotal",       self.vt_key,       "VT_API_KEY"),
            ("AbuseIPDB",        self.abuse_key,    "ABUSEIPDB_API_KEY"),
            ("AlienVault OTX",   self.otx_key,      "OTX_API_KEY"),
            ("Hybrid Analysis",  self.hybrid_key,   "HYBRID_ANALYSIS_API_KEY"),
            ("CAPE Sandbox",     "built-in",        "N/A (public)"),
            ("MalShare",         self.malshare_key, "MALSHARE_API_KEY"),
        ]

        for name, key, env in providers:
            if key == "built-in":
                status = Text("✔ Public", style="green")
            elif key:
                status = Text("✔ Set",   style="green")
            else:
                status = Text("✘ Missing", style="yellow")
            table.add_row(name, status, env)

        console.print(table)
        console.print()

    def _render_ioc_header(self, ioc: str, ioc_type: str):
        """Render an IOC summary panel."""
        text = Text()
        text.append("  IOC  : ", style="bold white")
        text.append(ioc, style="bold cyan")
        text.append("\n  Type : ", style="bold white")
        text.append(ioc_type.upper(), style="bold yellow")
        console.print(Panel(text, title="[bold white]◈ Scanning IOC", border_style="cyan"))

    def _render_results_table(self, ioc: str, ioc_type: str, results: list):
        """
        Render a Rich table of all provider results for a single IOC.

        Color-codes the Verdict column by severity.
        """
        table = Table(
            title=f"[bold white]Results for [cyan]{ioc}[/cyan] ([yellow]{ioc_type.upper()}[/yellow])",
            box=box.DOUBLE_EDGE,
            border_style="bright_blue",
            show_header=True,
            header_style="bold white on dark_blue",
            row_styles=["", "dim"],
        )

        table.add_column("Provider",   style="bold white", min_width=18)
        table.add_column("Field",      style="white",      min_width=16)
        table.add_column("Value",      min_width=20)
        table.add_column("Verdict",    min_width=12)

        for r in results:
            source  = r.get("source", "Unknown")
            verdict = r.get("verdict", "unknown")
            error   = r.get("error")
            v_color = severity_color(verdict)

            if error:
                # Show error row in dim
                table.add_row(
                    source,
                    "Error",
                    Text(error, style="dim red"),
                    Text("⚠ Error", style="dim yellow")
                )
                continue

            # Provider-specific field extraction
            if source == "VirusTotal":
                table.add_row(
                    source,
                    "Detection Ratio",
                    r.get("detection", "N/A"),
                    Text(verdict.upper(), style=v_color)
                )
            elif source == "AbuseIPDB":
                conf  = r.get("confidence", "N/A")
                rep   = r.get("total_reports", "N/A")
                cntry = r.get("country", "N/A")
                table.add_row(
                    source,
                    "Confidence Score",
                    f"{conf}  │  Reports: {rep}  │  Country: {cntry}",
                    Text(verdict.upper(), style=v_color)
                )
            elif source == "AlienVault OTX":
                pulses  = r.get("pulses", "N/A")
                families = r.get("malware_families", "N/A")
                table.add_row(
                    source,
                    "Pulses / Families",
                    f"Pulses: {pulses}  │  Families: {families}",
                    Text(verdict.upper(), style=v_color)
                )
            elif source == "Hybrid Analysis":
                score  = r.get("threat_score", "N/A")
                family = r.get("malware_family", "N/A")
                av     = r.get("av_detect", "N/A")
                table.add_row(
                    source,
                    "Threat Score",
                    f"Score: {score}/100  │  Family: {family}  │  AV: {av}",
                    Text(verdict.upper(), style=v_color)
                )
            elif source == "CAPE Sandbox":
                task_id    = r.get("task_id", "N/A")
                detections = r.get("detections", "N/A")
                table.add_row(
                    source,
                    "Detections",
                    f"Task: {task_id}  │  Detections: {detections}",
                    Text(verdict.upper(), style=v_color)
                )
            elif source == "MalShare":
                found     = r.get("found", "N/A")
                file_type = r.get("file_type", "N/A")
                table.add_row(
                    source,
                    "Repository",
                    f"Found: {found}  │  Type: {file_type}",
                    Text(verdict.upper(), style=v_color)
                )
            else:
                table.add_row(source, "Result", str(r), Text(verdict.upper(), style=v_color))

        console.print(table)

    def _render_ioc_summary(self, ioc: str, ioc_type: str, results: list):
        """Render a compact IOC summary panel (SOC-style)."""
        # Aggregate verdict
        verdicts = [r.get("verdict", "unknown") for r in results if not r.get("error")]
        if any(v == "malicious"  for v in verdicts):
            overall   = "MALICIOUS"
            ov_style  = "bold red"
        elif any(v == "suspicious" for v in verdicts):
            overall   = "SUSPICIOUS"
            ov_style  = "bold yellow"
        elif all(v == "clean"      for v in verdicts) and verdicts:
            overall   = "CLEAN"
            ov_style  = "bold green"
        else:
            overall   = "UNKNOWN"
            ov_style  = "bold white"

        # Build summary lines
        lines = Text()
        lines.append(f"  IOC          : ", style="white"); lines.append(ioc + "\n",       style="bold cyan")
        lines.append(f"  Type         : ", style="white"); lines.append(ioc_type.upper() + "\n", style="bold yellow")
        lines.append(f"  Overall      : ", style="white"); lines.append(overall + "\n",   style=ov_style)
        lines.append("  ─────────────────────────────────\n", style="dim")

        for r in results:
            src = r.get("source", "?")
            v   = r.get("verdict", "unknown")
            err = r.get("error")
            color = severity_color(v)
            if err:
                lines.append(f"  {src:<20}: ", style="white")
                lines.append(f"Error – {err}\n", style="dim red")
            else:
                lines.append(f"  {src:<20}: ", style="white")
                lines.append(v.upper() + "\n", style=color)

        console.print(Panel(lines, title="[bold white]◈ IOC SUMMARY",
                            border_style=ov_style.split()[-1]))
        console.print()

    # ── Core dispatch methods ─────────────────────────────────────────────────

    def _run_concurrent(self, tasks: list) -> list:
        """
        Execute a list of (callable, *args) tuples concurrently.

        Returns a list of results in completion order.
        """
        results = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(fn, *args): fn.__name__ for fn, *args in tasks}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append({
                        "source":  futures[future],
                        "verdict": "unknown",
                        "error":   str(exc)
                    })
        return results

    def check_ip(self, ip: str):
        """Run all applicable checks for an IP address."""
        self._render_ioc_header(ip, "ip")

        tasks = [
            (self.vt.check_virustotal,        ip, "ip"),
            (self.abuse.check_abuseipdb,      ip),
            (self.otx.check_otx,              ip, "ip"),
        ]
        results = self._run_concurrent(tasks)
        self._render_results_table(ip, "ip", results)
        self._render_ioc_summary(ip, "ip", results)

    def check_domain(self, domain: str):
        """Run all applicable checks for a domain."""
        self._render_ioc_header(domain, "domain")

        tasks = [
            (self.vt.check_virustotal, domain, "domain"),
            (self.otx.check_otx,       domain, "domain"),
        ]
        results = self._run_concurrent(tasks)
        self._render_results_table(domain, "domain", results)
        self._render_ioc_summary(domain, "domain", results)

    def check_url(self, url: str):
        """Run all applicable checks for a URL."""
        self._render_ioc_header(url, "url")

        tasks = [
            (self.vt.check_virustotal, url, "url"),
            (self.otx.check_otx,       url, "url"),
        ]
        results = self._run_concurrent(tasks)
        self._render_results_table(url, "url", results)
        self._render_ioc_summary(url, "url", results)

    def check_hash(self, file_hash: str):
        """Run all applicable checks for a file hash."""
        ioc_type = detect_ioc_type(file_hash)
        if ioc_type == 'unknown':
            ioc_type = 'hash'  # fallback label

        self._render_ioc_header(file_hash, ioc_type)

        tasks = [
            (self.vt.check_virustotal,            file_hash, ioc_type),
            (self.otx.check_otx,                  file_hash, ioc_type),
            (self.hybrid.check_hybrid_analysis,   file_hash, ioc_type),
            (self.cape.check_cape,                file_hash, ioc_type),
            (self.malshare.check_malshare,        file_hash, ioc_type),
        ]
        results = self._run_concurrent(tasks)
        self._render_results_table(file_hash, ioc_type, results)
        self._render_ioc_summary(file_hash, ioc_type, results)

    def scan_file(self, file_path: str):
        """
        Compute hashes for a local file, display them, then run hash checks.

        The SHA256 hash is used for threat intelligence lookups.
        """
        console.print(f"\n[bold cyan]◈ Scanning local file:[/] [white]{file_path}[/white]")

        try:
            hashes = compute_file_hashes(file_path)
        except (FileNotFoundError, IOError) as e:
            console.print(f"[bold red]✘ Error:[/] {e}")
            return

        # Display computed hashes in a clean table
        hash_table = Table(title="File Hashes", box=box.SIMPLE_HEAVY,
                           title_style="bold cyan")
        hash_table.add_column("Algorithm", style="bold yellow", width=10)
        hash_table.add_column("Hash Value", style="white")

        hash_table.add_row("MD5",    hashes['md5'])
        hash_table.add_row("SHA1",   hashes['sha1'])
        hash_table.add_row("SHA256", Text(hashes['sha256'], style="bold green"))
        console.print(hash_table)

        console.print("[dim]→ Using SHA256 for threat intelligence lookups...[/dim]\n")

        # Run threat intelligence checks on SHA256
        self.check_hash(hashes['sha256'])

    def run(self, args):
        """
        Main entry point — routes parsed CLI arguments to the correct checkers.

        Supports multiple simultaneous IOC arguments.
        """
        self._print_banner()
        self._api_key_status_table()

        any_check = False

        if args.file:
            any_check = True
            self.scan_file(args.file)

        if args.ip:
            for ip in args.ip:
                ip = ip.strip()
                if detect_ioc_type(ip) not in ('ip',):
                    console.print(f"[yellow]⚠ Warning:[/] '{ip}' does not look like a valid IP address. Skipping.")
                    continue
                any_check = True
                self.check_ip(ip)
                console.print(Rule(style="dim"))

        if args.domain:
            for domain in args.domain:
                domain = domain.strip()
                any_check = True
                self.check_domain(domain)
                console.print(Rule(style="dim"))

        if args.url:
            for url in args.url:
                url = url.strip()
                any_check = True
                self.check_url(url)
                console.print(Rule(style="dim"))

        if args.hash:
            for h in args.hash:
                h = h.strip()
                ioc_type = detect_ioc_type(h)
                if ioc_type not in ('md5', 'sha1', 'sha256'):
                    console.print(f"[yellow]⚠ Warning:[/] '{h}' does not look like a valid hash (MD5/SHA1/SHA256). Attempting anyway.")
                any_check = True
                self.check_hash(h)
                console.print(Rule(style="dim"))

        if not any_check:
            console.print("[yellow]No IOC provided. Use --help for usage.[/yellow]")


# =============================================================================
# Entry Point
# =============================================================================

def build_argument_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="ioc_checker.py",
        description=(
            "╔══════════════════════════════════════════════╗\n"
            "║  IOC Checker — SOC Threat Intelligence Tool  ║\n"
            "╚══════════════════════════════════════════════╝\n"
            "Query VirusTotal, AbuseIPDB, OTX, Hybrid Analysis,\n"
            "CAPE Sandbox, and MalShare for IOC reputation.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python ioc_checker.py --ip 8.8.8.8\n"
            "  python ioc_checker.py --domain malware.example.com\n"
            "  python ioc_checker.py --url http://malicious.site/payload\n"
            "  python ioc_checker.py --hash d41d8cd98f00b204e9800998ecf8427e\n"
            "  python ioc_checker.py -f /samples/malware.exe\n"
            "  python ioc_checker.py --ip 1.2.3.4 --url http://bad.com --hash abc123...\n"
            "\n"
            "Required Environment Variables:\n"
            "  VT_API_KEY              VirusTotal API key\n"
            "  ABUSEIPDB_API_KEY       AbuseIPDB API key\n"
            "  OTX_API_KEY             AlienVault OTX API key\n"
            "  HYBRID_ANALYSIS_API_KEY Hybrid Analysis API key\n"
            "  MALSHARE_API_KEY        MalShare API key\n"
        )
    )

    parser.add_argument(
        "--ip", nargs="+", metavar="IP",
        help="One or more IP addresses to check (e.g., --ip 8.8.8.8 1.1.1.1)"
    )
    parser.add_argument(
        "--domain", nargs="+", metavar="DOMAIN",
        help="One or more domain names to check"
    )
    parser.add_argument(
        "--url", nargs="+", metavar="URL",
        help="One or more URLs to check (must include http:// or https://)"
    )
    parser.add_argument(
        "--hash", nargs="+", metavar="HASH",
        help="One or more file hashes (MD5, SHA1, or SHA256)"
    )
    parser.add_argument(
        "-f", "--file", metavar="FILE_PATH",
        help="Path to a local file — hashes are auto-calculated and SHA256 is looked up"
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {TOOL_VERSION}"
    )

    return parser


def main():
    parser  = build_argument_parser()
    args    = parser.parse_args()

    # Show help if no arguments supplied at all
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    checker = IOCChecker()
    checker.run(args)


if __name__ == "__main__":
    main()
