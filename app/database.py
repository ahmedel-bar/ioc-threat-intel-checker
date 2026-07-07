import sqlite3
import threading
import json
from pathlib import Path
from contextlib import contextmanager
from app.config import Config

_local = threading.local()


def _open_conn() -> sqlite3.Connection:
    Path(Config.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-8000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_conn() -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = _open_conn()
    return _local.conn


@contextmanager
def tx():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ioc_indicators (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            value        TEXT    NOT NULL UNIQUE,
            type         TEXT    NOT NULL,
            threat_level TEXT    DEFAULT 'UNKNOWN',
            source       TEXT    DEFAULT 'extracted',
            vt_detections INTEGER DEFAULT 0,
            vt_total      INTEGER DEFAULT 0,
            vt_score      REAL    DEFAULT 0.0,
            metadata      TEXT    DEFAULT '{}',
            first_seen    TEXT    DEFAULT (datetime('now')),
            last_seen     TEXT    DEFAULT (datetime('now')),
            lookup_count  INTEGER DEFAULT 0
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_value  ON ioc_indicators(value);
        CREATE        INDEX IF NOT EXISTS idx_ioc_type   ON ioc_indicators(type);
        CREATE        INDEX IF NOT EXISTS idx_ioc_threat ON ioc_indicators(threat_level);

        CREATE TABLE IF NOT EXISTS alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_value  TEXT NOT NULL,
            indicator_type   TEXT NOT NULL,
            severity         TEXT NOT NULL,
            status           TEXT DEFAULT 'NEW',
            source_log       TEXT DEFAULT '',
            vt_report        TEXT DEFAULT '{}',
            analyst_note     TEXT DEFAULT '',
            mitre_technique  TEXT DEFAULT '',
            geo_info         TEXT DEFAULT '{}',
            correlation_id   INTEGER,
            created_at       TEXT DEFAULT (datetime('now')),
            acknowledged_at  TEXT,
            acknowledged_by  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_alert_status   ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alert_created  ON alerts(created_at);

        CREATE TABLE IF NOT EXISTS correlations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source_key  TEXT    NOT NULL,
            alert_count INTEGER DEFAULT 1,
            first_seen  TEXT    DEFAULT (datetime('now')),
            last_seen   TEXT    DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_corr_source ON correlations(source_key, last_seen);

        CREATE TABLE IF NOT EXISTS feed_sync_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name       TEXT    NOT NULL,
            records_added   INTEGER DEFAULT 0,
            duration_secs   REAL    DEFAULT 0,
            status          TEXT    DEFAULT 'SUCCESS',
            error_message   TEXT    DEFAULT '',
            synced_at       TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS pipeline_metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            value       REAL NOT NULL,
            recorded_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_metric_name ON pipeline_metrics(name, recorded_at);
    """)
    conn.commit()
    _migrate()


def _migrate():
    """Safely add columns and indexes introduced after initial schema deployment."""
    conn = get_conn()
    for stmt in [
        "ALTER TABLE alerts ADD COLUMN mitre_technique TEXT DEFAULT ''",
        "ALTER TABLE alerts ADD COLUMN geo_info TEXT DEFAULT '{}'",
        "ALTER TABLE alerts ADD COLUMN correlation_id INTEGER",
        "CREATE INDEX IF NOT EXISTS idx_alert_corr ON alerts(correlation_id)",
        "ALTER TABLE ioc_indicators ADD COLUMN allowlisted INTEGER DEFAULT 0",
        "CREATE INDEX IF NOT EXISTS idx_ioc_allowlisted ON ioc_indicators(allowlisted)",
    ]:
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass  # column or index already exists
    conn.commit()


# ── IOC CRUD ──────────────────────────────────────────────────────────────────

def upsert_ioc(value: str, ioc_type: str, source: str = "extracted") -> int:
    conn = get_conn()
    conn.execute("""
        INSERT INTO ioc_indicators (value, type, source)
        VALUES (?, ?, ?)
        ON CONFLICT(value) DO UPDATE SET
            last_seen    = datetime('now'),
            lookup_count = lookup_count + 1
    """, (value, ioc_type, source))
    conn.commit()
    row = conn.execute("SELECT id FROM ioc_indicators WHERE value = ?", (value,)).fetchone()
    return row["id"] if row else -1


def get_ioc(value: str) -> dict | None:
    row = get_conn().execute(
        "SELECT * FROM ioc_indicators WHERE value = ?", (value,)
    ).fetchone()
    return dict(row) if row else None


def update_ioc_vt(value: str, detections: int, total: int, score: float, report: dict):
    threat = "MALICIOUS" if score >= Config.VT_MALICIOUS_THRESHOLD else (
        "SUSPICIOUS" if score >= 0.05 else "CLEAN"
    )
    get_conn().execute("""
        UPDATE ioc_indicators
        SET threat_level=?, vt_detections=?, vt_total=?, vt_score=?,
            metadata=?, last_seen=datetime('now')
        WHERE value=?
    """, (threat, detections, total, score, json.dumps(report), value))
    get_conn().commit()
    return threat


def list_iocs(page: int = 1, per_page: int = 50,
              ioc_type: str = None, threat: str = None,
              search: str = None, source: str = None,
              sort: str = "last_seen", allowlisted: int = None) -> tuple[list[dict], int]:
    where_parts, params = [], []
    if ioc_type:
        where_parts.append("type = ?")
        params.append(ioc_type)
    if threat:
        where_parts.append("threat_level = ?")
        params.append(threat)
    if search:
        where_parts.append("value LIKE ?")
        params.append(f"%{search}%")
    if source:
        where_parts.append("source LIKE ?")
        params.append(f"%{source}%")
    if allowlisted is not None:
        where_parts.append("allowlisted = ?")
        params.append(allowlisted)
    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
    valid_sorts = {"last_seen", "first_seen", "lookup_count", "vt_score", "value"}
    sort_col = sort if sort in valid_sorts else "last_seen"
    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) FROM ioc_indicators {where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = conn.execute(
        f"SELECT * FROM ioc_indicators {where} ORDER BY {sort_col} DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()
    return [dict(r) for r in rows], total


def allowlist_ioc(ioc_id: int, flag: bool):
    conn = get_conn()
    conn.execute("UPDATE ioc_indicators SET allowlisted=? WHERE id=?", (1 if flag else 0, ioc_id))
    conn.commit()


def is_allowlisted(value: str) -> bool:
    row = get_conn().execute(
        "SELECT allowlisted FROM ioc_indicators WHERE value=?", (value,)
    ).fetchone()
    return bool(row and row["allowlisted"])


def get_ioc_detail(ioc_id: int) -> dict | None:
    conn = get_conn()
    ioc = conn.execute("SELECT * FROM ioc_indicators WHERE id=?", (ioc_id,)).fetchone()
    if not ioc:
        return None
    alerts = conn.execute(
        "SELECT id, severity, status, mitre_technique, geo_info, created_at, source_log "
        "FROM alerts WHERE indicator_value=? ORDER BY created_at DESC LIMIT 20",
        (ioc["value"],)
    ).fetchall()
    return {**dict(ioc), "alerts": [dict(a) for a in alerts]}


def bulk_delete_iocs(ids: list[int]):
    if not ids:
        return
    placeholders = ",".join("?" * len(ids))
    conn = get_conn()
    conn.execute(f"DELETE FROM ioc_indicators WHERE id IN ({placeholders})", ids)
    conn.commit()


def count_iocs_by_threat() -> dict:
    rows = get_conn().execute(
        "SELECT threat_level, COUNT(*) as cnt FROM ioc_indicators GROUP BY threat_level"
    ).fetchall()
    return {r["threat_level"]: r["cnt"] for r in rows}


def get_total_ioc_count() -> int:
    return get_conn().execute("SELECT COUNT(*) FROM ioc_indicators").fetchone()[0]


# ── Alert CRUD ────────────────────────────────────────────────────────────────

def has_recent_alert(value: str) -> bool:
    """True if an open NEW alert already exists for this IOC."""
    row = get_conn().execute(
        "SELECT COUNT(*) FROM alerts WHERE indicator_value = ? AND status = 'NEW'",
        (value,)
    ).fetchone()
    return row[0] > 0


def create_alert(indicator_value: str, indicator_type: str, severity: str,
                 source_log: str = "", vt_report: dict = None,
                 mitre_technique: str = "", geo_info: dict = None) -> int:
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO alerts
            (indicator_value, indicator_type, severity, source_log, vt_report,
             mitre_technique, geo_info)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (indicator_value, indicator_type, severity, source_log,
          json.dumps(vt_report or {}), mitre_technique, json.dumps(geo_info or {})))
    conn.commit()
    return cur.lastrowid


def list_alerts(page: int = 1, per_page: int = 50,
                status: str = None, severity: str = None,
                search: str = None) -> tuple[list[dict], int]:
    where_parts, params = [], []
    if status:
        where_parts.append("status = ?")
        params.append(status)
    if severity:
        where_parts.append("severity = ?")
        params.append(severity)
    if search:
        where_parts.append("indicator_value LIKE ?")
        params.append(f"%{search}%")
    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""
    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()
    return [dict(r) for r in rows], total


def acknowledge_alert(alert_id: int, analyst: str = "analyst", note: str = ""):
    conn = get_conn()
    conn.execute("""
        UPDATE alerts SET status='ACKNOWLEDGED', acknowledged_at=datetime('now'),
        acknowledged_by=?, analyst_note=? WHERE id=?
    """, (analyst, note, alert_id))
    conn.commit()


def false_positive_alert(alert_id: int):
    conn = get_conn()
    conn.execute(
        "UPDATE alerts SET status='FALSE_POSITIVE', acknowledged_at=datetime('now') WHERE id=?",
        (alert_id,)
    )
    conn.commit()


def count_alerts_today() -> int:
    return get_conn().execute(
        "SELECT COUNT(*) FROM alerts WHERE date(created_at)=date('now')"
    ).fetchone()[0]


def count_alerts_by_severity() -> dict:
    rows = get_conn().execute(
        "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
    ).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}


def get_alert_trend(hours: int = 24) -> list[dict]:
    """Hourly alert counts for the last N hours."""
    rows = get_conn().execute("""
        SELECT strftime('%Y-%m-%dT%H:00:00', created_at) as hour,
               COUNT(*) as cnt
        FROM alerts
        WHERE created_at >= datetime('now', ? || ' hours')
        GROUP BY strftime('%Y-%m-%dT%H', created_at)
        ORDER BY hour
    """, (f"-{hours}",)).fetchall()
    return [{"hour": r["hour"], "cnt": r["cnt"]} for r in rows]


# ── Correlations ──────────────────────────────────────────────────────────────

def get_or_create_correlation(source_key: str, window_minutes: int = 10) -> int:
    conn = get_conn()
    row = conn.execute("""
        SELECT id FROM correlations
        WHERE source_key = ?
          AND last_seen >= datetime('now', ? || ' minutes')
        ORDER BY last_seen DESC LIMIT 1
    """, (source_key, f"-{window_minutes}")).fetchone()
    if row:
        conn.execute(
            "UPDATE correlations SET last_seen=datetime('now'), alert_count=alert_count+1 WHERE id=?",
            (row["id"],)
        )
        conn.commit()
        return row["id"]
    cur = conn.execute("INSERT INTO correlations (source_key) VALUES (?)", (source_key,))
    conn.commit()
    return cur.lastrowid


def link_alert_to_correlation(alert_id: int, correlation_id: int):
    conn = get_conn()
    conn.execute("UPDATE alerts SET correlation_id=? WHERE id=?", (correlation_id, alert_id))
    conn.commit()


def get_active_correlations(limit: int = 10) -> list[dict]:
    rows = get_conn().execute("""
        SELECT c.id, c.source_key, c.alert_count, c.first_seen, c.last_seen,
               COUNT(a.id) as confirmed_alerts
        FROM correlations c
        LEFT JOIN alerts a ON a.correlation_id = c.id AND a.status != 'FALSE_POSITIVE'
        WHERE c.last_seen >= datetime('now', '-24 hours')
        GROUP BY c.id
        HAVING confirmed_alerts >= 2
        ORDER BY c.last_seen DESC
        LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


# ── Feed sync history ─────────────────────────────────────────────────────────

def log_feed_sync(feed_name: str, records: int, duration: float,
                  status: str = "SUCCESS", error: str = ""):
    conn = get_conn()
    conn.execute("""
        INSERT INTO feed_sync_history (feed_name, records_added, duration_secs, status, error_message)
        VALUES (?, ?, ?, ?, ?)
    """, (feed_name, records, duration, status, error))
    conn.commit()


def get_feed_sync_history(limit: int = 20) -> list[dict]:
    rows = get_conn().execute(
        "SELECT * FROM feed_sync_history ORDER BY synced_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ── Metrics ───────────────────────────────────────────────────────────────────

def record_metric(name: str, value: float):
    conn = get_conn()
    conn.execute(
        "INSERT INTO pipeline_metrics (name, value) VALUES (?, ?)", (name, value)
    )
    conn.commit()


def get_metric_series(name: str, hours: int = 24) -> list[dict]:
    rows = get_conn().execute("""
        SELECT strftime('%Y-%m-%dT%H:%M:00', recorded_at) as ts,
               AVG(value) as val
        FROM pipeline_metrics
        WHERE name=? AND recorded_at >= datetime('now', ? || ' hours')
        GROUP BY strftime('%Y-%m-%dT%H:%M', recorded_at)
        ORDER BY ts
    """, (name, f"-{hours}")).fetchall()
    return [{"ts": r["ts"], "val": round(r["val"], 2)} for r in rows]


def cleanup_old_metrics(days: int = 7):
    """Prune metrics older than N days to prevent unbounded table growth."""
    conn = get_conn()
    conn.execute(
        "DELETE FROM pipeline_metrics WHERE recorded_at < datetime('now', ? || ' days')",
        (f"-{days}",)
    )
    conn.commit()


def get_vt_quota_today() -> int:
    row = get_conn().execute(
        "SELECT value FROM pipeline_metrics WHERE name='vt_quota' AND date(recorded_at)=date('now') "
        "ORDER BY recorded_at DESC LIMIT 1"
    ).fetchone()
    return int(row["value"]) if row else 0


def save_vt_quota(count: int):
    record_metric("vt_quota", count)


def cleanup_old_alerts(days: int):
    conn = get_conn()
    conn.execute(
        "DELETE FROM alerts WHERE created_at < datetime('now', ? || ' days') AND status != 'NEW'",
        (f"-{days}",)
    )
    conn.commit()


def cleanup_old_iocs(days: int):
    conn = get_conn()
    conn.execute(
        "DELETE FROM ioc_indicators WHERE last_seen < datetime('now', ? || ' days') AND allowlisted = 0",
        (f"-{days}",)
    )
    conn.commit()
