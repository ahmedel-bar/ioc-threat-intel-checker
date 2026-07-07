import base64
import time
import threading
import logging
import requests

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
_DAILY_LIMIT = 500


class TokenBucket:
    """Thread-safe token bucket — default 4 requests / minute."""

    def __init__(self, rate_per_minute: int = 4):
        self._rate = rate_per_minute
        self._tokens = float(rate_per_minute)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._tokens = min(self._rate, self._tokens + elapsed * (self._rate / 60.0))
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
            time.sleep(0.5)


class VTBroker:
    def __init__(self, api_key: str, rate_per_minute: int = 4):
        self._key = api_key
        self._bucket = TokenBucket(rate_per_minute)
        self._day = time.strftime("%Y-%m-%d")
        self._lock = threading.Lock()
        # Restore today's count from DB so restarts don't reset quota tracking
        try:
            from app import database as _db
            self._queries_today = _db.get_vt_quota_today()
        except Exception:
            self._queries_today = 0

    @property
    def queries_today(self) -> int:
        return self._queries_today

    @property
    def quota_remaining(self) -> int:
        return max(0, _DAILY_LIMIT - self._queries_today)

    def _reset_if_new_day(self):
        today = time.strftime("%Y-%m-%d")
        with self._lock:
            if today != self._day:
                self._day = today
                self._queries_today = 0

    def _endpoint(self, value: str, ioc_type: str) -> str:
        if ioc_type == "ip":
            return f"{VT_BASE}/ip_addresses/{value}"
        if ioc_type in ("md5", "sha1", "sha256"):
            return f"{VT_BASE}/files/{value}"
        if ioc_type == "domain":
            return f"{VT_BASE}/domains/{value}"
        if ioc_type == "url":
            encoded = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
            return f"{VT_BASE}/urls/{encoded}"
        raise ValueError(f"Unknown IOC type: {ioc_type}")

    def query(self, value: str, ioc_type: str) -> dict | None:
        if not self._key:
            return None
        self._reset_if_new_day()
        if self._queries_today >= _DAILY_LIMIT:
            logger.warning("[VT] Daily quota exhausted")
            return None

        self._bucket.acquire()
        try:
            url = self._endpoint(value, ioc_type)
            resp = requests.get(url, headers={"x-apikey": self._key}, timeout=15)
            with self._lock:
                self._queries_today += 1

            if resp.status_code == 200:
                result = self._parse(resp.json())
                self._persist_quota()
                return result
            if resp.status_code == 404:
                self._persist_quota()
                return {"detections": 0, "total": 0, "score": 0.0, "raw": {}}
            logger.warning("[VT] %s returned %d for %s", url, resp.status_code, value)
            return None
        except requests.RequestException as exc:
            logger.error("[VT] Request failed for %s: %s", value, exc)
            return None

    def _persist_quota(self):
        try:
            from app import database as _db
            _db.save_vt_quota(self._queries_today)
        except Exception:
            pass

    @staticmethod
    def _parse(data: dict) -> dict:
        try:
            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            score = (malicious + suspicious) / total
            return {
                "detections": malicious + suspicious,
                "total": total,
                "score": round(score, 4),
                "raw": stats,
            }
        except (KeyError, TypeError):
            return {"detections": 0, "total": 0, "score": 0.0, "raw": {}}
