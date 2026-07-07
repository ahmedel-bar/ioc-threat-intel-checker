import time
import logging
import requests
import csv
import io

from app import database as db
from app.config import Config

logger = logging.getLogger(__name__)

FEEDS = [
    {
        "name": "Feodo Tracker (IP Blocklist)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "parser": "feodo_ip",
    },
    {
        "name": "URLHaus (Recent URLs)",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "parser": "urlhaus_csv",
    },
    {
        "name": "Abuse.ch SSL Blacklist",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "parser": "sslbl_ip",
    },
]


def _parse_feodo_ip(text: str) -> list[tuple[str, str]]:
    iocs = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ip = line.split()[0]
            iocs.append((ip, "ip"))
    return iocs


def _parse_urlhaus_csv(text: str) -> list[tuple[str, str]]:
    iocs = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        # columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        if len(row) >= 3:
            url = row[2].strip().strip('"')
            if url.startswith("http"):
                iocs.append((url.lower(), "url"))
    return iocs


def _parse_sslbl_ip(text: str) -> list[tuple[str, str]]:
    iocs = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if row and not row[0].startswith("#") and len(row) >= 2:
            ip = row[1].strip()
            if ip and ip != "DstIP":
                iocs.append((ip, "ip"))
    return iocs


_UPSERT_SQL = """
    INSERT INTO ioc_indicators (value, type, threat_level, source)
    VALUES (?, ?, 'MALICIOUS', ?)
    ON CONFLICT(value) DO UPDATE SET
        threat_level = 'MALICIOUS',
        last_seen    = datetime('now'),
        source       = excluded.source
"""


def _bulk_insert(iocs: list[tuple[str, str]], source: str) -> int:
    if not iocs:
        return 0
    conn = db.get_conn()
    params = [(value, ioc_type, source) for value, ioc_type in iocs]
    try:
        conn.executemany(_UPSERT_SQL, params)
        conn.commit()
        return len(iocs)
    except Exception as exc:
        logger.debug("[SYNC] batch insert failed for %s, falling back to row-by-row: %s", source, exc)
        conn.rollback()
    added = 0
    for p in params:
        try:
            conn.execute(_UPSERT_SQL, p)
            added += 1
        except Exception as exc:
            logger.debug("[SYNC] skipped IOC %s: %s", p[0], exc)
    conn.commit()
    return added


def sync_all() -> dict:
    summary = {}
    for feed in FEEDS:
        t0 = time.monotonic()
        try:
            resp = requests.get(feed["url"], timeout=30)
            resp.raise_for_status()
            if feed["parser"] == "feodo_ip":
                iocs = _parse_feodo_ip(resp.text)
            elif feed["parser"] == "urlhaus_csv":
                iocs = _parse_urlhaus_csv(resp.text)
            elif feed["parser"] == "sslbl_ip":
                iocs = _parse_sslbl_ip(resp.text)
            else:
                iocs = []

            added = _bulk_insert(iocs, feed["name"])
            duration = time.monotonic() - t0
            db.log_feed_sync(feed["name"], added, duration, "SUCCESS")
            logger.info("[SYNC] %s: %d IOCs added (%.1fs)", feed["name"], added, duration)
            summary[feed["name"]] = {"added": added, "status": "SUCCESS"}

        except Exception as exc:
            duration = time.monotonic() - t0
            db.log_feed_sync(feed["name"], 0, duration, "ERROR", str(exc))
            logger.error("[SYNC] %s failed: %s", feed["name"], exc)
            summary[feed["name"]] = {"added": 0, "status": "ERROR", "error": str(exc)}

    # Optional: AlienVault OTX (requires API key)
    if Config.OTX_API_KEY:
        t0 = time.monotonic()
        try:
            headers = {"X-OTX-API-KEY": Config.OTX_API_KEY}
            resp = requests.get(
                "https://otx.alienvault.com/api/v1/indicators/export?type=IPv4",
                headers=headers, timeout=30
            )
            resp.raise_for_status()
            iocs = []
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    iocs.append((line, "ip"))
            added = _bulk_insert(iocs, "AlienVault OTX")
            duration = time.monotonic() - t0
            db.log_feed_sync("AlienVault OTX", added, duration, "SUCCESS")
            summary["AlienVault OTX"] = {"added": added, "status": "SUCCESS"}
        except Exception as exc:
            duration = time.monotonic() - t0
            db.log_feed_sync("AlienVault OTX", 0, duration, "ERROR", str(exc))
            summary["AlienVault OTX"] = {"status": "ERROR", "error": str(exc)}

    return summary
