import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    DATABASE_PATH = str(BASE_DIR / "data" / "ioc_cache.db")

    # Splunk
    USE_SIMULATOR = os.getenv("USE_SIMULATOR", "true").lower() == "true"
    SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
    SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
    SPLUNK_SCHEME = os.getenv("SPLUNK_SCHEME", "https")
    SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
    SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
    SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
    SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "*")
    SPLUNK_SEARCH = os.getenv(
        "SPLUNK_SEARCH",
        "search index=* sourcetype=pan:traffic OR sourcetype=linux_secure OR sourcetype=access_combined",
    )
    SPLUNK_EARLIEST = os.getenv("SPLUNK_EARLIEST", "rt-5m")
    SPLUNK_LATEST = os.getenv("SPLUNK_LATEST", "rt")

    # VirusTotal
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    VT_MALICIOUS_THRESHOLD = float(os.getenv("VT_MALICIOUS_THRESHOLD", "0.15"))
    VT_RATE_LIMIT = int(os.getenv("VT_RATE_LIMIT", "4"))

    # Threat feeds
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    FEED_SYNC_INTERVAL_HOURS = int(os.getenv("FEED_SYNC_INTERVAL_HOURS", "6"))

    # Pipeline
    SIMULATOR_RATE = int(os.getenv("SIMULATOR_RATE", "30"))
    PARSER_WORKERS = int(os.getenv("PARSER_WORKERS", "4"))
    FILTER_RFC1918 = os.getenv("FILTER_RFC1918", "true").lower() == "true"

    # Enrichment
    GEOIP_ENABLED = os.getenv("GEOIP_ENABLED", "true").lower() == "true"

    # Notifications
    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

    # Retention
    ALERT_RETENTION_DAYS = int(os.getenv("ALERT_RETENTION_DAYS", "90"))
    IOC_RETENTION_DAYS   = int(os.getenv("IOC_RETENTION_DAYS",   "30"))

    # Adversary emulation
    EMULATION_ENABLED       = os.getenv("EMULATION_ENABLED", "true").lower() == "true"
    EMULATION_SEED_ON_BOOT  = os.getenv("EMULATION_SEED_ON_BOOT", "true").lower() == "true"
    EMULATION_DEFAULT_ENGINE = os.getenv("EMULATION_DEFAULT_ENGINE", "tabletop")  # tabletop|atomic|caldera
    CALDERA_URL             = os.getenv("CALDERA_URL", "http://localhost:8888")
    CALDERA_API_KEY         = os.getenv("CALDERA_API_KEY", "")
