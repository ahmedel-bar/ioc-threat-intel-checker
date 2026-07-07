# Project Anatomy — siem-intel

A Flask + SocketIO real-time SIEM threat intelligence platform.

## Entry Points
- `run.py` — starts Flask/SocketIO server, boots pipeline. ~22 lines.
- `app/__init__.py` — `create_app()` factory: registers blueprint, inits DB, warns on default SECRET_KEY. ~33 lines.

## Core Pipeline
- `app/pipeline.py` — orchestrates all background threads (ingest, parser, lookup, VT, feed sync, stats broadcast). Shared queues: ingest_queue(10k), ioc_queue(50k), vt_queue(2k). ~291 lines.
- `app/config.py` — Config class reads all settings from env/.env at import time. ~46 lines.

## Database
- `app/database.py` — SQLite WAL, thread-local connections, full CRUD for IOCs/alerts/correlations/metrics. Tables: ioc_indicators, alerts, correlations, feed_sync_history, pipeline_metrics. ~406 lines.

## Ingestion
- `app/ingestion/simulator.py` — generates synthetic log events at configurable rate.
- `app/ingestion/splunk_client.py` — SplunkIngester reads all config from Config class.

## Parsing
- `app/parsing/extractor.py` — extracts IOCs (ip, domain, url, md5, sha1, sha256) from raw log strings. RFC-1918 filtering support.

## Enrichment
- `app/enrichment/virustotal.py` — VTBroker with TokenBucket rate limiter, daily quota tracking (persisted to DB). ~126 lines.
- `app/enrichment/feed_sync.py` — syncs Feodo IP, URLHaus CSV, SSLBL, optional OTX feeds. Uses executemany bulk insert with row-by-row fallback. ~150 lines.
- `app/enrichment/geoip.py` — lightweight geo-IP lookup for alert enrichment.

## Alerts
- `app/alerts/engine.py` — evaluates IOC threat score → creates alert with MITRE tag + geo + correlation. Emits SocketIO alert_new event. ~93 lines.
- `app/alerts/mitre.py` — MITRE ATT&CK technique tagging by IOC type + log pattern.

## Routes / API
- `app/routes.py` — Flask Blueprint: dashboard/alerts/ioc-browser/settings pages + full REST API (~512 lines). Endpoints: /api/stats, /api/health, /api/alerts, /api/iocs, /api/feeds, /api/config, /api/test/inject, /api/test/reset, /api/correlations, /api/db/info, /api/splunk/test.

## Templates
- `templates/base.html` — base layout (Tailwind dark theme, Alpine.js, SocketIO).
- `templates/dashboard.html` — real-time stats cards, queue gauges, alert trend chart, attack simulation panel.
- `templates/alerts.html` — paginated alert table with ack/FP actions, export.
- `templates/ioc_browser.html` — searchable/filterable IOC table with bulk delete.
- `templates/settings.html` — VT/Splunk/feed/pipeline config form + DB info panel.

## Tests
- `tests/test_extractor.py` — IOC extraction unit tests.
- `tests/test_database.py` — database CRUD tests.
- `tests/test_vt_broker.py` — VTBroker tests (mocked requests).
- `tests/test_new_features.py` — tests for MITRE, geo, correlation, alert trend, export.

## Data
- `data/ioc_cache.db` — SQLite WAL database (runtime, excluded from git).

## Config / Meta
- `.env` — secrets (VT_API_KEY, SPLUNK_TOKEN, etc.) — excluded from git.
- `.gitignore` — excludes .env, data/*.db, __pycache__, venv, etc.
- `requirements.txt` — Python dependencies.
