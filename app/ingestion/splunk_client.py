"""
Real Splunk ingestion via splunklib SDK.
Falls back gracefully if splunk-sdk is not installed.
Supports username/password and bearer-token auth.
"""
import time
import queue
import threading
import logging

from app.config import Config

logger = logging.getLogger(__name__)

try:
    import splunklib.client as splunk_client
    import splunklib.results as splunk_results
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    logger.warning("[Splunk] splunk-sdk not installed — run: pip install splunk-sdk")


class SplunkIngester:
    def __init__(self):
        self._service = None

    def _build_connect_kwargs(self) -> dict:
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
        return kwargs

    def _connect(self):
        if not _SDK_AVAILABLE:
            raise RuntimeError(
                "splunk-sdk not installed. Run: pip install splunk-sdk"
            )
        kwargs = self._build_connect_kwargs()
        self._service = splunk_client.connect(**kwargs)
        logger.info(
            "[Splunk] Connected → %s:%d (%s) auth=%s",
            Config.SPLUNK_HOST, Config.SPLUNK_PORT, Config.SPLUNK_SCHEME,
            "token" if Config.SPLUNK_TOKEN else "password",
        )

    def run(self, out_queue: queue.Queue, stop_event: threading.Event):
        backoff = [1, 1, 2, 3, 5, 8, 13, 21, 34, 60]
        attempt = 0

        while not stop_event.is_set():
            try:
                self._connect()
                attempt = 0

                search_params = {
                    "exec_mode":    "normal",
                    "earliest_time": Config.SPLUNK_EARLIEST,
                    "latest_time":   Config.SPLUNK_LATEST,
                    "output_mode":   "json",
                }

                while not stop_event.is_set():
                    job = self._service.jobs.create(Config.SPLUNK_SEARCH, **search_params)

                    while not job.is_done() and not stop_event.is_set():
                        time.sleep(0.5)

                    for result in splunk_results.JSONResultsReader(job.results(output_mode="json")):
                        if isinstance(result, dict) and not out_queue.full():
                            out_queue.put({
                                "sourcetype": result.get("sourcetype", "splunk"),
                                "host":       result.get("host", "unknown"),
                                "_raw":       result.get("_raw", str(result)),
                            })

                    job.cancel()
                    # Pause between polls — rt-5m means re-run every 30s is fine
                    time.sleep(30)

            except Exception as exc:
                delay = backoff[min(attempt, len(backoff) - 1)]
                logger.error("[Splunk] Error: %s — retry in %ds", exc, delay)
                attempt += 1
                time.sleep(delay)
