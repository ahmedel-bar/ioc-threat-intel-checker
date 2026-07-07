"""
Tests for all features added in session 3:
  - MITRE ATT&CK tagging
  - Geo-IP enrichment (mocked)
  - IOC correlation
  - Alert trend query
  - Bulk IOC delete
  - VT quota persistence
  - Metrics cleanup
  - has_recent_alert (status-based)
  - create_alert with new fields
  - API routes: export, bulk-delete, correlations, alert-trend, health
"""
import os
import json
import pytest
import tempfile
from unittest.mock import patch, MagicMock

# ── Temp DB setup ──────────────────────────────────────────────────────────────
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["DATABASE_PATH"] = _tmp_db.name

from app.config import Config
Config.DATABASE_PATH = _tmp_db.name

from app import database as db


@pytest.fixture(autouse=True)
def fresh_db():
    db.init_db()
    yield
    conn = db.get_conn()
    for tbl in ("ioc_indicators", "alerts", "correlations",
                "feed_sync_history", "pipeline_metrics"):
        conn.execute(f"DELETE FROM {tbl}")
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK tagging
# ─────────────────────────────────────────────────────────────────────────────
class TestMitre:
    def test_ssh_bruteforce_log(self):
        from app.alerts.mitre import tag
        result = tag("ip", "sshd[3412]: Failed password for root from 1.2.3.4")
        assert result["technique_id"] == "T1110"
        assert result["tactic"] == "Credential Access"

    def test_ransomware_log(self):
        from app.alerts.mitre import tag
        result = tag("url", "GET http://ransomware-drop.ru/payload.exe HTTP/1.1")
        assert result["technique_id"] == "T1486"

    def test_c2_beacon_log(self):
        from app.alerts.mitre import tag
        result = tag("ip", "TRAFFIC ALLOW 194.165.16.77:4444 -> 10.0.0.1:443 beacon")
        assert result["technique_id"] == "T1071.001"

    def test_phishing_url(self):
        from app.alerts.mitre import tag
        result = tag("url", "GET http://phish-login.tk/steal.php HTTP/1.1")
        assert result["technique_id"] == "T1566.002"

    def test_tor_exit(self):
        from app.alerts.mitre import tag
        result = tag("ip", "TRAFFIC DENY 198.98.51.189:9001 rule=block-tor")
        assert result["technique_id"] == "T1090.003"

    def test_hash_type_default(self):
        from app.alerts.mitre import tag
        result = tag("md5", "some unrelated log line")
        assert result["technique_id"] == "T1204.002"
        assert result["tactic"] == "Execution"

    def test_domain_type_default(self):
        from app.alerts.mitre import tag
        result = tag("domain", "")
        assert result["technique_id"] == "T1071.004"

    def test_unknown_type_fallback(self):
        from app.alerts.mitre import tag
        result = tag("unknown_type", "")
        assert "technique_id" in result
        assert result["technique_id"] == "T1071"

    def test_returns_required_keys(self):
        from app.alerts.mitre import tag
        result = tag("ip", "some log")
        assert "technique_id" in result
        assert "technique_name" in result
        assert "tactic" in result


# ─────────────────────────────────────────────────────────────────────────────
# Geo-IP enrichment
# ─────────────────────────────────────────────────────────────────────────────
class TestGeoIP:
    def test_successful_lookup(self):
        from app.enrichment import geoip
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "countryCode": "RU",
            "country": "Russia",
            "city": "Moscow",
            "org": "AS12345 Some ISP",
            "as": "AS12345 Some ISP",
        }
        with patch("app.enrichment.geoip.requests.get", return_value=mock_resp):
            geoip._CACHE.clear()
            result = geoip.lookup("185.220.101.47")
        assert result["country_code"] == "RU"
        assert result["country_name"] == "Russia"
        assert result["asn"] == "AS12345 Some ISP"

    def test_failed_lookup_returns_empty(self):
        from app.enrichment import geoip
        with patch("app.enrichment.geoip.requests.get", side_effect=Exception("timeout")):
            geoip._CACHE.clear()
            result = geoip.lookup("1.2.3.4")
        assert result == {}

    def test_api_failure_status(self):
        from app.enrichment import geoip
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "fail"}
        with patch("app.enrichment.geoip.requests.get", return_value=mock_resp):
            geoip._CACHE.clear()
            result = geoip.lookup("127.0.0.1")
        assert result == {}

    def test_result_is_cached(self):
        from app.enrichment import geoip
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success", "countryCode": "DE", "country": "Germany",
            "city": "Berlin", "org": "AS3320 DTAG", "as": "AS3320 DTAG",
        }
        geoip._CACHE.clear()
        with patch("app.enrichment.geoip.requests.get", return_value=mock_resp) as mock_get:
            geoip.lookup("8.8.8.8")
            geoip.lookup("8.8.8.8")  # second call should use cache
        assert mock_get.call_count == 1

    def test_empty_ip_returns_empty(self):
        from app.enrichment import geoip
        assert geoip.lookup("") == {}


# ─────────────────────────────────────────────────────────────────────────────
# IOC Correlation
# ─────────────────────────────────────────────────────────────────────────────
class TestCorrelation:
    def test_creates_new_correlation(self):
        cid = db.get_or_create_correlation("10.0.0.1")
        assert cid > 0

    def test_reuses_recent_correlation(self):
        cid1 = db.get_or_create_correlation("10.0.0.5")
        cid2 = db.get_or_create_correlation("10.0.0.5")
        assert cid1 == cid2

    def test_different_sources_different_correlation(self):
        cid1 = db.get_or_create_correlation("10.0.0.1")
        cid2 = db.get_or_create_correlation("10.0.0.2")
        assert cid1 != cid2

    def test_link_alert_to_correlation(self):
        cid = db.get_or_create_correlation("10.1.1.1")
        aid = db.create_alert("evil.com", "domain", "HIGH")
        db.link_alert_to_correlation(aid, cid)
        rows, _ = db.list_alerts()
        row = next(r for r in rows if r["id"] == aid)
        assert row["correlation_id"] == cid

    def test_active_correlations_requires_two_alerts(self):
        cid = db.get_or_create_correlation("10.5.5.5")
        # Only 1 alert linked — should NOT appear in active correlations
        aid = db.create_alert("a.com", "domain", "HIGH")
        db.link_alert_to_correlation(aid, cid)
        active = db.get_active_correlations()
        assert not any(c["id"] == cid for c in active)

        # Add a second alert
        cid = db.get_or_create_correlation("10.5.5.5")  # increments alert_count
        aid2 = db.create_alert("b.com", "domain", "HIGH")
        db.link_alert_to_correlation(aid2, cid)
        active = db.get_active_correlations()
        assert any(c["id"] == cid for c in active)


# ─────────────────────────────────────────────────────────────────────────────
# Database new functions
# ─────────────────────────────────────────────────────────────────────────────
class TestDatabaseNewFunctions:
    def test_create_alert_with_mitre_and_geo(self):
        geo = {"country_code": "US", "country_name": "United States"}
        aid = db.create_alert("5.6.7.8", "ip", "CRITICAL",
                              mitre_technique="T1110 · Brute Force", geo_info=geo)
        rows, _ = db.list_alerts()
        row = next(r for r in rows if r["id"] == aid)
        assert row["mitre_technique"] == "T1110 · Brute Force"
        assert json.loads(row["geo_info"])["country_code"] == "US"

    def test_has_recent_alert_blocks_on_new_status(self):
        db.create_alert("1.1.1.1", "ip", "HIGH")
        assert db.has_recent_alert("1.1.1.1") is True

    def test_has_recent_alert_clears_after_acknowledge(self):
        aid = db.create_alert("2.2.2.2", "ip", "HIGH")
        db.acknowledge_alert(aid)
        assert db.has_recent_alert("2.2.2.2") is False

    def test_has_recent_alert_false_positive_clears(self):
        aid = db.create_alert("3.3.3.3", "ip", "HIGH")
        db.false_positive_alert(aid)
        assert db.has_recent_alert("3.3.3.3") is False

    def test_alert_trend_returns_list(self):
        db.create_alert("x.com", "domain", "HIGH")
        trend = db.get_alert_trend(24)
        assert isinstance(trend, list)
        assert len(trend) >= 1
        assert "hour" in trend[0]
        assert "cnt" in trend[0]

    def test_bulk_delete_iocs(self):
        id1 = db.upsert_ioc("10.0.0.1", "ip")
        id2 = db.upsert_ioc("10.0.0.2", "ip")
        id3 = db.upsert_ioc("10.0.0.3", "ip")
        db.bulk_delete_iocs([id1, id2])
        assert db.get_ioc("10.0.0.1") is None
        assert db.get_ioc("10.0.0.2") is None
        assert db.get_ioc("10.0.0.3") is not None

    def test_bulk_delete_empty_list_no_error(self):
        db.bulk_delete_iocs([])  # should not raise

    def test_metrics_cleanup(self):
        db.record_metric("events_per_minute", 42)
        conn = db.get_conn()
        # Insert an old metric manually
        conn.execute(
            "INSERT INTO pipeline_metrics (name, value, recorded_at) VALUES (?, ?, datetime('now', '-10 days'))",
            ("events_per_minute", 99)
        )
        conn.commit()
        db.cleanup_old_metrics(days=7)
        rows = conn.execute(
            "SELECT * FROM pipeline_metrics WHERE name='events_per_minute' AND recorded_at < datetime('now', '-7 days')"
        ).fetchall()
        assert len(rows) == 0

    def test_vt_quota_persistence(self):
        assert db.get_vt_quota_today() == 0
        db.save_vt_quota(42)
        assert db.get_vt_quota_today() == 42
        db.save_vt_quota(100)
        assert db.get_vt_quota_today() == 100


# ─────────────────────────────────────────────────────────────────────────────
# Alert engine integration
# ─────────────────────────────────────────────────────────────────────────────
class TestAlertEngine:
    def setup_method(self):
        from app.alerts import engine
        engine.init(None)

    def test_evaluate_creates_alert_with_mitre(self):
        from app.alerts import engine
        Config.VT_MALICIOUS_THRESHOLD = 0.15
        with patch("app.enrichment.geoip.lookup", return_value={}):
            raised = engine.evaluate(
                "185.220.101.47", "ip",
                {"score": 0.90, "detections": 45, "total": 70},
                "sshd[3412]: Failed password for root from 185.220.101.47"
            )
        assert raised is True
        rows, _ = db.list_alerts()
        row = rows[0]
        assert "T1110" in row["mitre_technique"]

    def test_evaluate_creates_alert_with_geo(self):
        from app.alerts import engine
        Config.VT_MALICIOUS_THRESHOLD = 0.15
        geo_data = {"country_code": "RU", "country_name": "Russia"}
        with patch("app.enrichment.geoip.lookup", return_value=geo_data):
            engine.evaluate(
                "1.2.3.4", "ip",
                {"score": 0.80, "detections": 40, "total": 70},
                "TRAFFIC ALLOW 1.2.3.4:443"
            )
        rows, _ = db.list_alerts()
        geo = json.loads(rows[0]["geo_info"])
        assert geo["country_code"] == "RU"

    def test_evaluate_no_geo_for_non_ip(self):
        from app.alerts import engine
        Config.VT_MALICIOUS_THRESHOLD = 0.15
        with patch("app.enrichment.geoip.lookup") as mock_geo:
            engine.evaluate(
                "44d88612fea8a8f36de82e1278abb02f", "md5",
                {"score": 0.90, "detections": 45, "total": 70},
                "EventCode=4688"
            )
        mock_geo.assert_not_called()

    def test_evaluate_below_threshold_no_alert(self):
        from app.alerts import engine
        Config.VT_MALICIOUS_THRESHOLD = 0.15
        with patch("app.enrichment.geoip.lookup", return_value={}):
            raised = engine.evaluate("clean.com", "domain", {"score": 0.01}, "")
        assert raised is False
        _, total = db.list_alerts()
        assert total == 0

    def test_evaluate_cooldown_blocks_duplicate(self):
        from app.alerts import engine
        Config.VT_MALICIOUS_THRESHOLD = 0.15
        with patch("app.enrichment.geoip.lookup", return_value={}):
            r1 = engine.evaluate("evil.com", "domain", {"score": 0.90}, "")
            r2 = engine.evaluate("evil.com", "domain", {"score": 0.90}, "")
        assert r1 is True
        assert r2 is False
        _, total = db.list_alerts()
        assert total == 1

    def test_evaluate_correlation_links_same_source(self):
        from app.alerts import engine
        Config.VT_MALICIOUS_THRESHOLD = 0.15
        log1 = "10.0.1.5 triggered: evil.com"
        log2 = "10.0.1.5 triggered: malware.ru"
        with patch("app.enrichment.geoip.lookup", return_value={}):
            engine.evaluate("evil.com", "domain", {"score": 0.90}, log1)
            engine.evaluate("malware.ru", "domain", {"score": 0.90}, log2)
        rows, _ = db.list_alerts()
        # Both alerts should share the same correlation_id
        cids = {r["correlation_id"] for r in rows if r["correlation_id"]}
        assert len(cids) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Flask API routes
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestAPIRoutes:
    def test_health_endpoint_returns_queues(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "OK"
        assert "queues" in data
        assert "ingest" in data["queues"]

    def test_alert_trend_endpoint(self, client):
        r = client.get("/api/metrics/alert-trend?hours=24")
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)

    def test_correlations_endpoint(self, client):
        r = client.get("/api/correlations")
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)

    def test_export_csv(self, client):
        db.create_alert("evil.com", "domain", "HIGH")
        r = client.get("/api/alerts/export?format=csv")
        assert r.status_code == 200
        assert "text/csv" in r.content_type
        text = r.data.decode()
        assert "indicator_value" in text  # CSV header
        assert "evil.com" in text

    def test_export_json(self, client):
        db.create_alert("bad.ip", "ip", "CRITICAL")
        r = client.get("/api/alerts/export?format=json")
        assert r.status_code == 200
        data = r.get_json()
        assert isinstance(data, list)
        assert any(a["indicator_value"] == "bad.ip" for a in data)

    def test_export_filtered_by_severity(self, client):
        db.create_alert("critical.com", "domain", "CRITICAL")
        db.create_alert("low.com", "domain", "LOW")
        r = client.get("/api/alerts/export?format=json&severity=CRITICAL")
        data = r.get_json()
        assert all(a["severity"] == "CRITICAL" for a in data)

    def test_bulk_delete_iocs(self, client):
        id1 = db.upsert_ioc("10.1.1.1", "ip")
        id2 = db.upsert_ioc("10.1.1.2", "ip")
        r = client.post("/api/iocs/bulk-delete",
                        json={"ids": [id1, id2]},
                        content_type="application/json")
        assert r.status_code == 200
        assert r.get_json()["deleted"] == 2
        assert db.get_ioc("10.1.1.1") is None
        assert db.get_ioc("10.1.1.2") is None

    def test_bulk_delete_empty_ids_returns_400(self, client):
        r = client.post("/api/iocs/bulk-delete", json={"ids": []},
                        content_type="application/json")
        assert r.status_code == 400

    def test_inject_validates_long_value(self, client):
        r = client.post("/api/test/inject",
                        json={"value": "x" * 600, "type": "ip"},
                        content_type="application/json")
        # Value is truncated to 500 chars — should still succeed (ip type valid)
        assert r.status_code in (200, 503)

    def test_inject_validates_bad_type(self, client):
        r = client.post("/api/test/inject",
                        json={"value": "1.2.3.4", "type": "notavalidtype"},
                        content_type="application/json")
        assert r.status_code == 400

    def test_test_reset_endpoint(self, client):
        db.create_alert("x.com", "domain", "HIGH")
        r = client.post("/api/test/reset")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert data["cleared"] >= 1
