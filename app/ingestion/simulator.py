"""
Generates realistic synthetic security log events for demo/testing
without requiring a live Splunk instance.
"""
import random
import time
import queue
import threading
from datetime import datetime, timezone

# ── Known malicious seeds (will trigger VT / alert) ───────────────────────────
MALICIOUS_IPS = [
    "185.220.101.47", "194.165.16.77", "45.33.32.156",
    "91.108.4.1", "198.98.51.189", "176.10.104.240",
]
MALICIOUS_DOMAINS = [
    "malware-c2.xyz", "phish-login.tk", "ransomware-drop.ru",
    "botnet-beacon.top", "dga-x7k9.monster",
]
MALICIOUS_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 (empty file — known)
    "a94a8fe5ccb19ba61c4c0873d391e987d9b1d6",  # SHA1
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
]

# ── Benign pools ───────────────────────────────────────────────────────────────
BENIGN_IPS = [f"203.{r}.{c}.{h}" for r in range(5) for c in range(5) for h in range(5)]
BENIGN_DOMAINS = [
    "updates.microsoft.com", "dl.google.com", "cdn.cloudflare.com",
    "fonts.googleapis.com", "s3.amazonaws.com", "api.github.com",
    "telemetry.ubuntu.com", "ntp.ubuntu.com",
]

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "curl/7.88.1",
    "python-requests/2.31.0",
]

SOURCE_TYPES = [
    "pan:traffic", "linux_secure", "access_combined",
    "wineventlog", "syslog",
]

ATTACK_TYPES = [
    "port_scan", "brute_force", "sql_injection",
    "malware_beacon", "data_exfil",
]


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _random_ip(malicious_chance: float = 0.05) -> str:
    if random.random() < malicious_chance:
        return random.choice(MALICIOUS_IPS)
    return random.choice(BENIGN_IPS)


def _random_domain(malicious_chance: float = 0.05) -> str:
    if random.random() < malicious_chance:
        return random.choice(MALICIOUS_DOMAINS)
    return random.choice(BENIGN_DOMAINS)


def _random_hash(malicious_chance: float = 0.08) -> str:
    if random.random() < malicious_chance:
        return random.choice(MALICIOUS_HASHES)
    # Random benign MD5
    return "".join(random.choices("0123456789abcdef", k=32))


def _make_firewall_log() -> dict:
    src = _random_ip()
    dst = f"10.{random.randint(0,5)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return {
        "sourcetype": "pan:traffic",
        "host": f"fw-{random.randint(1,3)}.corp.local",
        "_raw": (
            f"{_ts()} TRAFFIC ALLOW {src}:{random.randint(1024,65535)} "
            f"-> {dst}:{random.choice([80,443,8080,22,3389])} "
            f"rule=allow-internet bytes={random.randint(200,1_500_000)}"
        ),
    }


def _make_auth_log() -> dict:
    ip = _random_ip(malicious_chance=0.08)
    status = random.choice(["Accepted", "Failed", "Failed", "Failed"])
    user = random.choice(["root", "admin", "ubuntu", "oracle", "deploy", "git"])
    return {
        "sourcetype": "linux_secure",
        "host": f"web-{random.randint(1,10)}.corp.local",
        "_raw": (
            f"{_ts()} sshd[{random.randint(1000,9999)}]: "
            f"{status} password for {user} from {ip} port {random.randint(1024,65535)}"
        ),
    }


def _make_web_log() -> dict:
    dom = _random_domain(malicious_chance=0.07)
    path = random.choice(["/", "/wp-admin/", "/api/v1/users", "/.env", "/shell.php"])
    ip = _random_ip()
    code = random.choice([200, 200, 200, 302, 404, 403, 500])
    return {
        "sourcetype": "access_combined",
        "host": "nginx-proxy.corp.local",
        "_raw": (
            f'{ip} - - [{_ts()}] "GET https://{dom}{path} HTTP/1.1" '
            f'{code} {random.randint(200, 80000)} '
            f'"{random.choice(BENIGN_USER_AGENTS)}"'
        ),
    }


def _make_endpoint_log() -> dict:
    h = _random_hash(malicious_chance=0.06)
    return {
        "sourcetype": "wineventlog",
        "host": f"ws-{random.randint(1,50)}.corp.local",
        "_raw": (
            f"{_ts()} EventCode=4688 Process=C:\\Windows\\System32\\cmd.exe "
            f"Hash={h} User=CORP\\{random.choice(['jsmith','alee','bkumar','mzhang'])} "
            f"CommandLine=\"{random.choice(['net user','whoami','ipconfig /all','dir c:\\'])}\""
        ),
    }


def _make_dns_log() -> dict:
    dom = _random_domain(malicious_chance=0.09)
    ip = _random_ip()
    return {
        "sourcetype": "syslog",
        "host": "dns-01.corp.local",
        "_raw": (
            f"{_ts()} named[1234]: client {ip}#53: "
            f"query: {dom} IN A NOERROR"
        ),
    }


_GENERATORS = [
    _make_firewall_log,
    _make_auth_log,
    _make_web_log,
    _make_endpoint_log,
    _make_dns_log,
]


def run_simulator(out_queue: queue.Queue, rate_per_sec, stop_event: threading.Event,
                  pause_event: threading.Event = None):
    get_rate = (lambda: rate_per_sec[0]) if isinstance(rate_per_sec, list) else (lambda: rate_per_sec)
    while not stop_event.is_set():
        if pause_event and pause_event.is_set():
            time.sleep(0.5)
            continue
        log = random.choice(_GENERATORS)()
        if not out_queue.full():
            out_queue.put(log)
        time.sleep(1.0 / max(1, get_rate()))
