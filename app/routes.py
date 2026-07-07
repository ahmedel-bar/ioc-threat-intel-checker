import json
import os
import sqlite3
from pathlib import Path
from flask import Blueprint, render_template, jsonify, request
from flask_socketio import emit
from app import database as db, socketio
from app import pipeline
from app.config import Config
from app.enrichment import feed_sync

bp = Blueprint("main", __name__)


# ── Pages ─────────────────────────────────────────────────────────────────────

@bp.get("/")
def dashboard():
    return render_template("dashboard.html")


@bp.get("/alerts")
def alerts_page():
    return render_template("alerts.html")


@bp.get("/ioc-browser")
def ioc_browser():
    return render_template("ioc_browser.html")


@bp.get("/settings")
def settings():
    return render_template("settings.html")


# ── Stats & health ────────────────────────────────────────────────────────────

@bp.get("/api/stats")
def api_stats():
    return jsonify(pipeline.get_stats())


@bp.get("/api/health")
def api_health():
    stats = pipeline.get_stats()
    return jsonify({
        "status": "OK",
        "pipeline_active": not pipeline._stop_event.is_set(),
        "ingestion_mode":  stats["ingestion_mode"],
        "vt_enabled":      bool(Config.VT_API_KEY),
        "ioc_db_total":    stats["ioc_db_total"],
        "alerts_today":    stats["alerts_today"],
        "queues": {
            "ingest": {"size": stats["queue_ingest"], "max": stats["queue_ingest_max"]},
            "ioc":    {"size": stats["queue_ioc"],    "max": stats["queue_ioc_max"]},
            "vt":     {"size": stats["queue_vt"],     "max": stats["queue_vt_max"]},
        },
        "uptime_seconds": stats["uptime_seconds"],
    })


@bp.get("/api/metrics/timeseries")
def api_timeseries():
    name = request.args.get("name", "events_per_minute")
    hours = int(request.args.get("hours", 1))
    return jsonify(db.get_metric_series(name, hours))


@bp.get("/api/metrics/summary")
def api_metrics_summary():
    return jsonify({
        "threat_distribution": db.count_iocs_by_threat(),
        "alert_severity": db.count_alerts_by_severity(),
    })


@bp.get("/api/metrics/alert-trend")
def api_alert_trend():
    hours = int(request.args.get("hours", 24))
    return jsonify(db.get_alert_trend(hours))


# ── Alerts ────────────────────────────────────────────────────────────────────

@bp.get("/api/alerts")
def api_alerts():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    status = request.args.get("status")
    severity = request.args.get("severity")
    search = request.args.get("search")
    rows, total = db.list_alerts(page, per_page, status, severity, search)
    return jsonify({"alerts": rows, "total": total, "page": page, "per_page": per_page})


@bp.post("/api/alerts/<int:alert_id>/acknowledge")
def api_ack_alert(alert_id: int):
    data = request.get_json(silent=True) or {}
    db.acknowledge_alert(alert_id, data.get("analyst", "analyst"), data.get("note", ""))
    return jsonify({"ok": True})


@bp.post("/api/alerts/<int:alert_id>/false-positive")
def api_fp_alert(alert_id: int):
    db.false_positive_alert(alert_id)
    return jsonify({"ok": True})


@bp.get("/api/alerts/export")
def api_alerts_export():
    import csv
    import io
    from flask import Response
    fmt      = request.args.get("format", "csv")
    status   = request.args.get("status")
    severity = request.args.get("severity")
    rows, _  = db.list_alerts(1, 10_000, status, severity)

    if fmt == "json":
        return jsonify(rows)

    fields = ["id", "indicator_value", "indicator_type", "severity", "status",
              "mitre_technique", "geo_info", "created_at", "acknowledged_at", "source_log"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fields})

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=siem-alerts.csv"},
    )


@bp.get("/api/correlations")
def api_correlations():
    return jsonify(db.get_active_correlations())


# ── IOC Browser ───────────────────────────────────────────────────────────────

@bp.get("/api/iocs")
def api_iocs():
    page      = int(request.args.get("page", 1))
    per_page  = int(request.args.get("per_page", 50))
    ioc_type  = request.args.get("type")
    threat    = request.args.get("threat")
    search    = request.args.get("search")
    source    = request.args.get("source")
    sort      = request.args.get("sort", "last_seen")
    allowlisted_param = request.args.get("allowlisted")
    allowlisted = int(allowlisted_param) if allowlisted_param in ("0", "1") else None
    rows, total = db.list_iocs(page, per_page, ioc_type, threat, search, source, sort, allowlisted)
    return jsonify({"iocs": rows, "total": total, "page": page, "per_page": per_page})


@bp.get("/api/iocs/lookup")
def api_ioc_lookup():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "q required"}), 400
    row = db.get_ioc(q)
    if not row:
        return jsonify({"found": False, "value": q})
    return jsonify({"found": True, **row})


@bp.get("/api/iocs/export")
def api_iocs_export():
    import csv
    import io
    from flask import Response
    ioc_type = request.args.get("type")
    threat   = request.args.get("threat")
    source   = request.args.get("source")
    rows, _  = db.list_iocs(1, 200_000, ioc_type, threat, source=source)
    fields   = ["id", "value", "type", "threat_level", "source", "vt_detections",
                "vt_total", "vt_score", "first_seen", "last_seen", "lookup_count", "allowlisted"]
    output   = io.StringIO()
    writer   = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fields})
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=siem-iocs.csv"},
    )


@bp.post("/api/iocs")
def api_add_ioc():
    data = request.get_json()
    if not data or not data.get("value") or not data.get("type"):
        return jsonify({"error": "value and type required"}), 400
    valid_types = {"ip", "domain", "url", "md5", "sha1", "sha256"}
    if data["type"] not in valid_types:
        return jsonify({"error": f"type must be one of {valid_types}"}), 400
    ioc_id = db.upsert_ioc(data["value"].strip(), data["type"], "manual")
    return jsonify({"ok": True, "id": ioc_id}), 201


@bp.get("/api/iocs/<int:ioc_id>/detail")
def api_ioc_detail(ioc_id: int):
    detail = db.get_ioc_detail(ioc_id)
    if not detail:
        return jsonify({"error": "not found"}), 404
    return jsonify(detail)


@bp.post("/api/iocs/<int:ioc_id>/allowlist")
def api_allowlist_ioc(ioc_id: int):
    data = request.get_json() or {}
    flag = bool(data.get("allowlisted", True))
    db.allowlist_ioc(ioc_id, flag)
    return jsonify({"ok": True, "allowlisted": flag})


@bp.delete("/api/iocs/<int:ioc_id>")
def api_delete_ioc(ioc_id: int):
    with db.tx() as conn:
        conn.execute("DELETE FROM ioc_indicators WHERE id=?", (ioc_id,))
    return jsonify({"ok": True})


@bp.post("/api/iocs/bulk-delete")
def api_bulk_delete_iocs():
    data = request.get_json() or {}
    ids = [int(i) for i in data.get("ids", []) if str(i).isdigit()]
    if not ids:
        return jsonify({"error": "ids required"}), 400
    db.bulk_delete_iocs(ids)
    return jsonify({"ok": True, "deleted": len(ids)})


# ── Test / Attack Simulation ─────────────────────────────────────────────────

# Pre-built attack scenarios: realistic logs containing confirmed-malicious IOCs
_SCENARIOS = {
    "ssh_bruteforce": {
        "label": "SSH Brute-Force",
        "ioc_value": "185.220.101.47",
        "ioc_type": "ip",
        "log": (
            "{ts} sshd[3412]: Failed password for root from 185.220.101.47 port 52100\n"
            "{ts} sshd[3412]: Failed password for admin from 185.220.101.47 port 52101\n"
            "{ts} sshd[3412]: Failed password for ubuntu from 185.220.101.47 port 52102"
        ),
    },
    "c2_beacon": {
        "label": "Malware C2 Beacon",
        "ioc_value": "194.165.16.77",
        "ioc_type": "ip",
        "log": (
            "{ts} TRAFFIC ALLOW 194.165.16.77:4444 -> 10.0.5.22:443 "
            "rule=allow-internet bytes=98304 app=ssl"
        ),
    },
    "dns_c2": {
        "label": "C2 DNS Query",
        "ioc_value": "malware-c2.xyz",
        "ioc_type": "domain",
        "log": (
            "{ts} named[999]: client 10.0.1.15#53: "
            "query: malware-c2.xyz IN A NOERROR"
        ),
    },
    "malicious_hash": {
        "label": "Malicious File Execution",
        "ioc_value": "44d88612fea8a8f36de82e1278abb02f",
        "ioc_type": "md5",
        "log": (
            "{ts} EventCode=4688 Process=C:\\Users\\Public\\evil.exe "
            "Hash=44d88612fea8a8f36de82e1278abb02f "
            "User=CORP\\jsmith CommandLine=\"evil.exe --silent\""
        ),
    },
    "phishing_url": {
        "label": "Phishing URL Access",
        "ioc_value": "http://phish-login.tk/steal.php",
        "ioc_type": "url",
        "log": (
            '10.0.2.33 - - [{ts}] "GET http://phish-login.tk/steal.php HTTP/1.1" '
            '200 4096 "Mozilla/5.0"'
        ),
    },
    "data_exfil": {
        "label": "Data Exfiltration",
        "ioc_value": "176.10.104.240",
        "ioc_type": "ip",
        "log": (
            "{ts} TRAFFIC ALLOW 10.0.1.8:51200 -> 176.10.104.240:443 "
            "rule=allow-internet bytes=52428800 app=ssl duration=3600"
        ),
    },
    "ransomware_drop": {
        "label": "Ransomware Download",
        "ioc_value": "http://ransomware-drop.ru/payload.exe",
        "ioc_type": "url",
        "log": (
            '10.0.3.11 - - [{ts}] "GET http://ransomware-drop.ru/payload.exe HTTP/1.1" '
            '200 1048576 "python-requests/2.28"'
        ),
    },
    "tor_exit": {
        "label": "Tor Exit Node Traffic",
        "ioc_value": "198.98.51.189",
        "ioc_type": "ip",
        "log": (
            "{ts} TRAFFIC DENY 198.98.51.189:9001 -> 10.0.5.1:443 "
            "rule=block-tor bytes=0 app=tor"
        ),
    },
}


@bp.get("/api/test/scenarios")
def api_test_scenarios():
    return jsonify([
        {"id": k, "label": v["label"], "ioc_value": v["ioc_value"], "ioc_type": v["ioc_type"]}
        for k, v in _SCENARIOS.items()
    ])


@bp.post("/api/test/inject")
def api_test_inject():
    """
    Inject a malicious event into the pipeline.
    Body: { "scenario": "ssh_bruteforce" }  — use a preset
       OR { "value": "1.2.3.4", "type": "ip", "raw_log": "..." }  — custom
    """
    from datetime import datetime, timezone
    from app.pipeline import ingest_queue

    data = request.get_json() or {}
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"

    scenario_id = data.get("scenario")
    if scenario_id:
        sc = _SCENARIOS.get(scenario_id)
        if not sc:
            return jsonify({"error": f"Unknown scenario '{scenario_id}'"}), 400
        ioc_value = sc["ioc_value"]
        ioc_type  = sc["ioc_type"]
        raw_log   = sc["log"].replace("{ts}", ts)
    else:
        ioc_value = data.get("value", "").strip()[:500]
        ioc_type  = data.get("type", "ip")
        raw_log   = data.get("raw_log", "").strip()[:2000]
        if not ioc_value:
            return jsonify({"error": "value or scenario required"}), 400
        valid_types = {"ip", "domain", "url", "md5", "sha1", "sha256"}
        if ioc_type not in valid_types:
            return jsonify({"error": f"type must be one of {sorted(valid_types)}"}), 400
        if not raw_log:
            raw_log = f"{ts} SUSPICIOUS indicator={ioc_value}"

    # Force-seed the IOC as MALICIOUS so the pipeline cache lookup fires immediately.
    # First, auto-acknowledge any open alert for this IOC so the cooldown never blocks repeated clicks.
    db.upsert_ioc(ioc_value, ioc_type, source="test_injection")
    conn = db.get_conn()
    conn.execute(
        "UPDATE alerts SET status='ACKNOWLEDGED', acknowledged_at=datetime('now'), acknowledged_by='sim_reset' "
        "WHERE indicator_value=? AND status='NEW'",
        (ioc_value,)
    )
    conn.execute(
        "UPDATE ioc_indicators SET threat_level='MALICIOUS', vt_score=0.95 WHERE value=?",
        (ioc_value,)
    )
    conn.commit()

    # Push log into the live pipeline
    if ingest_queue.full():
        return jsonify({"error": "Ingestion queue full — try again"}), 503

    ingest_queue.put({
        "sourcetype": "test_injection",
        "host":       "attacker.corp.local",
        "_raw":       raw_log,
    })

    return jsonify({"ok": True, "ioc_value": ioc_value, "ioc_type": ioc_type, "log": raw_log})


@bp.post("/api/test/reset")
def api_test_reset():
    """Acknowledge all open alerts so the simulation panel can fire fresh ones."""
    conn = db.get_conn()
    result = conn.execute(
        "UPDATE alerts SET status='ACKNOWLEDGED', acknowledged_at=datetime('now'), acknowledged_by='sim_reset' "
        "WHERE status='NEW'"
    )
    conn.commit()
    return jsonify({"ok": True, "cleared": result.rowcount})


# ── Pipeline Controls ─────────────────────────────────────────────────────────

@bp.post("/api/pipeline/pause")
def api_pipeline_pause():
    pipeline.pause()
    return jsonify({"ok": True, "paused": True})


@bp.post("/api/pipeline/resume")
def api_pipeline_resume():
    pipeline.resume()
    return jsonify({"ok": True, "paused": False})


@bp.post("/api/pipeline/speed")
def api_pipeline_speed():
    data = request.get_json() or {}
    rate = int(data.get("rate", 30))
    pipeline.set_simulator_rate(rate)
    return jsonify({"ok": True, "rate": rate})


# ── Feed Sync ──────────────────────────────────────────────────────────────────

@bp.get("/api/feeds/history")
def api_feed_history():
    return jsonify(db.get_feed_sync_history())


@bp.post("/api/feeds/sync")
def api_trigger_sync():
    import threading
    def _run():
        feed_sync.sync_all()
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "message": "Feed sync started in background"})


# ── Splunk connection test ────────────────────────────────────────────────────

@bp.get("/api/splunk/test")
def api_splunk_test():
    try:
        import splunklib.client as sc
        kwargs = dict(
            host=Config.SPLUNK_HOST,
            port=Config.SPLUNK_PORT,
            scheme=Config.SPLUNK_SCHEME,
        )
        if Config.SPLUNK_TOKEN:
            kwargs["splunkToken"] = Config.SPLUNK_TOKEN
        else:
            kwargs["username"] = Config.SPLUNK_USERNAME
            kwargs["password"] = Config.SPLUNK_PASSWORD
        svc = sc.connect(**kwargs)
        info = svc.info
        return jsonify({
            "ok": True,
            "version": info.get("version", "unknown"),
            "build": info.get("build", ""),
            "server_name": info.get("serverName", ""),
            "os": info.get("os_name", ""),
        })
    except ImportError:
        return jsonify({"ok": False, "error": "splunk-sdk not installed — run: pip install splunk-sdk"})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)})


# ── Database info ─────────────────────────────────────────────────────────────

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


@bp.get("/api/db/info")
def api_db_info():
    path = Path(Config.DATABASE_PATH)
    size = path.stat().st_size if path.exists() else 0
    conn = db.get_conn()
    tables = {}
    for tbl in ("ioc_indicators", "alerts", "feed_sync_history", "pipeline_metrics"):
        tables[tbl] = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
    sqlite_ver = sqlite3.sqlite_version
    return jsonify({
        "engine": "SQLite",
        "sqlite_version": sqlite_ver,
        "path": str(path.resolve()),
        "size_bytes": size,
        "size_human": _human_size(size),
        "tables": tables,
        "wal_mode": conn.execute("PRAGMA journal_mode").fetchone()[0].upper(),
    })


# ── Config ────────────────────────────────────────────────────────────────────

@bp.get("/api/config")
def api_get_config():
    return jsonify({
        # VT
        "vt_api_key_set": bool(Config.VT_API_KEY),
        "vt_threshold": Config.VT_MALICIOUS_THRESHOLD,
        "vt_rate_limit": Config.VT_RATE_LIMIT,
        # Splunk
        "use_simulator": Config.USE_SIMULATOR,
        "simulator_rate": Config.SIMULATOR_RATE,
        "splunk_host": Config.SPLUNK_HOST,
        "splunk_port": Config.SPLUNK_PORT,
        "splunk_scheme": Config.SPLUNK_SCHEME,
        "splunk_username": Config.SPLUNK_USERNAME,
        "splunk_token_set": bool(Config.SPLUNK_TOKEN),
        "splunk_index": Config.SPLUNK_INDEX,
        "splunk_search": Config.SPLUNK_SEARCH,
        "splunk_earliest": Config.SPLUNK_EARLIEST,
        "splunk_latest": Config.SPLUNK_LATEST,
        # Feeds
        "feed_sync_hours": Config.FEED_SYNC_INTERVAL_HOURS,
        "otx_key_set": bool(Config.OTX_API_KEY),
        # Pipeline
        "filter_rfc1918": Config.FILTER_RFC1918,
        # Notifications
        "webhook_url": Config.WEBHOOK_URL,
        # Retention
        "alert_retention_days": Config.ALERT_RETENTION_DAYS,
        "ioc_retention_days": Config.IOC_RETENTION_DAYS,
    })


_ENV_MAP = {
    "vt_api_key":           ("VT_API_KEY",                  lambda v: v if v else None),
    "vt_threshold":         ("VT_MALICIOUS_THRESHOLD",      str),
    "vt_rate_limit":        ("VT_RATE_LIMIT",               str),
    "use_simulator":        ("USE_SIMULATOR",               lambda v: "true" if v else "false"),
    "simulator_rate":       ("SIMULATOR_RATE",              str),
    "splunk_host":          ("SPLUNK_HOST",                 str),
    "splunk_port":          ("SPLUNK_PORT",                 str),
    "splunk_scheme":        ("SPLUNK_SCHEME",               str),
    "splunk_username":      ("SPLUNK_USERNAME",             str),
    "splunk_password":      ("SPLUNK_PASSWORD",             lambda v: v if v else None),
    "splunk_token":         ("SPLUNK_TOKEN",                lambda v: v if v else None),
    "splunk_index":         ("SPLUNK_INDEX",                str),
    "splunk_search":        ("SPLUNK_SEARCH",               str),
    "splunk_earliest":      ("SPLUNK_EARLIEST",             str),
    "splunk_latest":        ("SPLUNK_LATEST",               str),
    "feed_sync_hours":      ("FEED_SYNC_INTERVAL_HOURS",    str),
    "otx_api_key":          ("OTX_API_KEY",                 lambda v: v if v else None),
    "filter_rfc1918":       ("FILTER_RFC1918",              lambda v: "true" if v else "false"),
    "webhook_url":          ("WEBHOOK_URL",                 str),
    "alert_retention_days": ("ALERT_RETENTION_DAYS",        str),
    "ioc_retention_days":   ("IOC_RETENTION_DAYS",          str),
}


@bp.post("/api/config")
def api_save_config():
    data = request.get_json()
    if not data:
        return jsonify({"error": "no data"}), 400
    env_path = Path(__file__).resolve().parent.parent / ".env"
    updates = {}
    for field, (env_key, transform) in _ENV_MAP.items():
        if field in data:
            val = transform(data[field])
            if val is not None:
                updates[env_key] = val

    try:
        lines = env_path.read_text().splitlines(keepends=True) if env_path.exists() else []
        new_lines, applied = [], set()
        for line in lines:
            key = line.split("=")[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}\n")
                applied.add(key)
            else:
                new_lines.append(line)
        for key, val in updates.items():
            if key not in applied:
                new_lines.append(f"{key}={val}\n")
        env_path.write_text("".join(new_lines))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({"ok": True, "message": "Saved. Restart the server to apply changes."})


# ── SocketIO events ───────────────────────────────────────────────────────────

@socketio.on("connect", namespace="/live")
def on_connect():
    emit("stats_update", pipeline.get_stats())
