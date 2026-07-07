import re
import threading
import logging

from app import database as db
from app.config import Config
from app.alerts import mitre
from app.enrichment import geoip

logger = logging.getLogger(__name__)

_socketio = None
_lock = threading.Lock()

# RFC-1918 source-IP pattern for correlation grouping
_RFC1918_RE = re.compile(
    r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})\b'
)


def init(socketio):
    global _socketio
    _socketio = socketio


def _severity_from_score(score: float) -> str:
    if score >= 0.70:
        return "CRITICAL"
    if score >= 0.40:
        return "HIGH"
    if score >= 0.15:
        return "MEDIUM"
    return "LOW"


def _extract_source_key(source_log: str) -> str | None:
    """Return the first internal IP found in the log, used to group correlated alerts."""
    m = _RFC1918_RE.search(source_log or "")
    return m.group(1) if m else None


def _fire_webhook(payload: dict):
    try:
        import requests as _req
        _req.post(Config.WEBHOOK_URL, json=payload, timeout=5)
    except Exception as exc:
        logger.warning("[WEBHOOK] Failed: %s", exc)


def evaluate(value: str, ioc_type: str, vt_result: dict, source_log: str = "") -> bool:
    """Returns True if a new alert was raised."""
    score = vt_result.get("score", 0.0)
    if score < Config.VT_MALICIOUS_THRESHOLD:
        return False

    if db.has_recent_alert(value):
        return False

    if db.is_allowlisted(value):
        logger.info("[ALERT] Suppressed — %s is allowlisted", value)
        return False

    severity = _severity_from_score(score)

    # MITRE ATT&CK tagging
    mitre_tag = mitre.tag(ioc_type, source_log)
    mitre_str = f"{mitre_tag['technique_id']} · {mitre_tag['technique_name']}"

    # Geo-IP enrichment (only for IP IOCs)
    geo = geoip.lookup(value) if ioc_type == "ip" else {}

    # Correlation: group alerts triggered by the same internal host
    source_key = _extract_source_key(source_log)
    correlation_id = db.get_or_create_correlation(source_key) if source_key else None

    alert_id = db.create_alert(value, ioc_type, severity, source_log, vt_result, mitre_str, geo)

    if correlation_id:
        db.link_alert_to_correlation(alert_id, correlation_id)

    logger.warning(
        "[ALERT] %s | %s | score=%.2f | sev=%s | %s",
        ioc_type.upper(), value, score, severity, mitre_str,
    )

    ws_payload = {
        "id":          alert_id,
        "indicator":   value,
        "type":        ioc_type,
        "severity":    severity,
        "score":       round(score * 100, 1),
        "detections":  vt_result.get("detections", 0),
        "total":       vt_result.get("total", 0),
        "mitre":       mitre_tag,
        "geo":         geo,
        "correlation_id": correlation_id,
    }

    if _socketio:
        with _lock:
            _socketio.emit("alert_new", ws_payload, namespace="/live")

    if Config.WEBHOOK_URL:
        import threading as _t
        _t.Thread(target=_fire_webhook, args=(ws_payload,), daemon=True).start()

    return True
