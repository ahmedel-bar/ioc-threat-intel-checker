"""
Orchestrates all background threads:
  ingest_thread  →  ingest_queue
  parser_threads →  ioc_queue
  lookup_thread  →  vt_queue
  vt_thread      →  (alert engine)
  sync_thread    →  (every 6 hours)
  stats_thread   →  (SocketIO broadcast every 5s)
"""
import queue
import threading
import time
import logging
from collections import deque
from datetime import datetime, timezone

from app.config import Config
from app import database as db
from app.parsing.extractor import extract, IOC
from app.enrichment.virustotal import VTBroker
from app.enrichment import feed_sync
from app.alerts import engine as alert_engine

logger = logging.getLogger(__name__)

# ── Shared queues ──────────────────────────────────────────────────────────────
ingest_queue: queue.Queue = queue.Queue(maxsize=10_000)
ioc_queue:    queue.Queue = queue.Queue(maxsize=50_000)
vt_queue:     queue.Queue = queue.Queue(maxsize=2_000)

# ── Runtime counters ───────────────────────────────────────────────────────────
_counters_lock = threading.Lock()
_counters = {
    "events_total": 0,
    "iocs_extracted": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "vt_queries": 0,
    "alerts_generated": 0,
}

# Rolling events-per-minute window (last 60 seconds)
_event_timestamps: deque = deque(maxlen=5_000)

_vt_broker: VTBroker | None = None
_stop_event  = threading.Event()
_pause_event = threading.Event()
_socketio = None
_start_time = datetime.now(timezone.utc)
_simulator_rate: list = [Config.SIMULATOR_RATE]


def pause():
    _pause_event.set()

def resume():
    _pause_event.clear()

def is_paused() -> bool:
    return _pause_event.is_set()

def set_simulator_rate(rate: int):
    _simulator_rate[0] = max(1, min(500, rate))


def _inc(key: str, by: int = 1):
    with _counters_lock:
        _counters[key] += by


def get_stats() -> dict:
    with _counters_lock:
        c = dict(_counters)
    now = time.monotonic()
    window_start = now - 60
    epm = sum(1 for t in _event_timestamps if t > window_start)
    total = c["cache_hits"] + c["cache_misses"]
    hit_rate = round(c["cache_hits"] / total * 100, 1) if total else 0.0
    uptime_secs = int((datetime.now(timezone.utc) - _start_time).total_seconds())
    return {
        **c,
        "paused": _pause_event.is_set(),
        "simulator_rate": _simulator_rate[0],
        "events_per_minute": epm,
        "cache_hit_rate": hit_rate,
        "ioc_db_total": db.get_total_ioc_count(),
        "alerts_today": db.count_alerts_today(),
        "vt_queries_today": _vt_broker.queries_today if _vt_broker else 0,
        "vt_quota_remaining": _vt_broker.quota_remaining if _vt_broker else 0,
        "uptime_seconds": uptime_secs,
        "ingestion_mode": "simulator" if Config.USE_SIMULATOR else "splunk",
        # Queue depth telemetry
        "queue_ingest":     ingest_queue.qsize(),
        "queue_ingest_max": 10_000,
        "queue_ioc":        ioc_queue.qsize(),
        "queue_ioc_max":    50_000,
        "queue_vt":         vt_queue.qsize(),
        "queue_vt_max":     2_000,
    }


# ── Thread: parser ─────────────────────────────────────────────────────────────
def _parser_worker():
    while not _stop_event.is_set():
        if _pause_event.is_set():
            time.sleep(0.5)
            continue
        try:
            log_event = ingest_queue.get(timeout=1)
        except queue.Empty:
            continue

        raw: str = log_event.get("_raw", "")
        iocs = extract(raw, filter_rfc1918=Config.FILTER_RFC1918)
        _inc("events_total")
        _inc("iocs_extracted", len(iocs))
        _event_timestamps.append(time.monotonic())

        source = log_event.get("_raw", "")[:200]
        for ioc in iocs:
            db.upsert_ioc(ioc.value, ioc.type)
            if not ioc_queue.full():
                ioc_queue.put((ioc, source))

        ingest_queue.task_done()


# ── Thread: cache lookup + VT router ──────────────────────────────────────────
def _lookup_worker():
    while not _stop_event.is_set():
        try:
            ioc, source_log = ioc_queue.get(timeout=1)
        except queue.Empty:
            continue

        existing = db.get_ioc(ioc.value)
        if existing and existing.get("threat_level") not in ("UNKNOWN", None):
            _inc("cache_hits")
            threat = existing["threat_level"]
            score  = existing.get("vt_score", 0.0) or 0.0

            if _socketio:
                _socketio.emit("ioc_extracted", {
                    "value": ioc.value,
                    "type": ioc.type,
                    "threat": threat,
                    "score": round(score * 100, 1),
                }, namespace="/live")

            # Fire alert for threat-feed-confirmed MALICIOUS/SUSPICIOUS IOCs
            # (deduplication is handled inside alert_engine.evaluate)
            if threat in ("MALICIOUS", "SUSPICIOUS"):
                # Use stored VT score if available, otherwise synthetic score from feed
                effective_score = score if score > 0 else (0.90 if threat == "MALICIOUS" else 0.30)
                vt_result = {
                    "score": effective_score,
                    "detections": existing.get("vt_detections", 0),
                    "total":      existing.get("vt_total", 0),
                }
                raised = alert_engine.evaluate(ioc.value, ioc.type, vt_result, source_log)
                if raised:
                    _inc("alerts_generated")
        else:
            _inc("cache_misses")
            if not vt_queue.full():
                vt_queue.put((ioc, source_log))
            elif _socketio:
                _socketio.emit("ioc_extracted", {
                    "value": ioc.value,
                    "type": ioc.type,
                    "threat": "UNKNOWN",
                    "score": 0,
                }, namespace="/live")

        ioc_queue.task_done()


# ── Thread: VirusTotal enrichment ──────────────────────────────────────────────
def _vt_worker():
    global _vt_broker
    if not _vt_broker:
        logger.info("[VT] No API key — VT enrichment disabled")
        while not _stop_event.is_set():
            try:
                ioc, _ = vt_queue.get(timeout=1)
                # Without a key, just mark as unknown and emit
                if _socketio:
                    _socketio.emit("ioc_extracted", {
                        "value": ioc.value, "type": ioc.type,
                        "threat": "UNKNOWN", "score": 0,
                    }, namespace="/live")
                vt_queue.task_done()
            except queue.Empty:
                continue
        return

    while not _stop_event.is_set():
        try:
            ioc, source_log = vt_queue.get(timeout=1)
        except queue.Empty:
            continue

        result = _vt_broker.query(ioc.value, ioc.type)
        _inc("vt_queries")

        if result:
            threat = db.update_ioc_vt(
                ioc.value, result["detections"], result["total"],
                result["score"], result["raw"]
            )
            if _socketio:
                _socketio.emit("ioc_extracted", {
                    "value": ioc.value,
                    "type": ioc.type,
                    "threat": threat,
                    "score": round(result["score"] * 100, 1),
                }, namespace="/live")

            raised = alert_engine.evaluate(ioc.value, ioc.type, result, source_log)
            if raised:
                _inc("alerts_generated")

        vt_queue.task_done()


# ── Thread: feed synchronization (every 6h) ───────────────────────────────────
def _sync_worker():
    next_sync = time.monotonic()
    interval = Config.FEED_SYNC_INTERVAL_HOURS * 3600
    while not _stop_event.is_set():
        if time.monotonic() >= next_sync:
            logger.info("[SYNC] Starting threat feed synchronization…")
            summary = feed_sync.sync_all()
            added = sum(v.get("added", 0) for v in summary.values())
            logger.info("[SYNC] Complete — %d total IOCs added", added)
            db.record_metric("feed_sync_iocs", added)
            db.cleanup_old_metrics(days=7)
            db.cleanup_old_alerts(Config.ALERT_RETENTION_DAYS)
            db.cleanup_old_iocs(Config.IOC_RETENTION_DAYS)
            next_sync = time.monotonic() + interval
        time.sleep(30)


# ── Thread: stats broadcaster (every 5s) ──────────────────────────────────────
def _stats_worker():
    while not _stop_event.is_set():
        time.sleep(5)
        if _socketio:
            stats = get_stats()
            db.record_metric("events_per_minute", stats["events_per_minute"])
            _socketio.emit("stats_update", stats, namespace="/live")


# ── Public: start/stop ────────────────────────────────────────────────────────
def start(socketio):
    global _vt_broker, _socketio, _start_time
    _socketio = socketio
    _start_time = datetime.now(timezone.utc)

    if Config.VT_API_KEY:
        _vt_broker = VTBroker(Config.VT_API_KEY, Config.VT_RATE_LIMIT)
        logger.info("[VT] Broker initialized (rate=%d/min)", Config.VT_RATE_LIMIT)
    else:
        logger.warning("[VT] No API key set — VirusTotal enrichment disabled")

    alert_engine.init(socketio)

    # Start parser workers
    for _ in range(Config.PARSER_WORKERS):
        t = threading.Thread(target=_parser_worker, daemon=True)
        t.start()

    # Start lookup worker
    threading.Thread(target=_lookup_worker, daemon=True).start()

    # Start VT worker
    threading.Thread(target=_vt_worker, daemon=True).start()

    # Start feed sync worker
    threading.Thread(target=_sync_worker, daemon=True).start()

    # Start stats broadcaster
    threading.Thread(target=_stats_worker, daemon=True).start()

    # Start ingestion source
    if Config.USE_SIMULATOR:
        from app.ingestion.simulator import run_simulator
        _simulator_rate[0] = Config.SIMULATOR_RATE
        t = threading.Thread(
            target=run_simulator,
            args=(ingest_queue, _simulator_rate, _stop_event, _pause_event),
            daemon=True,
        )
        t.start()
        logger.info("[INGEST] Simulator started at %d events/sec", Config.SIMULATOR_RATE)
    else:
        from app.ingestion.splunk_client import SplunkIngester
        ingester = SplunkIngester()
        t = threading.Thread(
            target=ingester.run,
            args=(ingest_queue, _stop_event),
            daemon=True,
        )
        t.start()
        logger.info(
            "[INGEST] Splunk ingester started → %s://%s:%d",
            Config.SPLUNK_SCHEME, Config.SPLUNK_HOST, Config.SPLUNK_PORT,
        )


def stop():
    _stop_event.set()
