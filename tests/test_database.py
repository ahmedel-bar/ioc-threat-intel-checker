import os
import pytest
import tempfile

# Point to a temp db before importing app modules
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
    # Clean tables between tests
    conn = db.get_conn()
    conn.execute("DELETE FROM ioc_indicators")
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM feed_sync_history")
    conn.commit()


class TestIOCCRUD:
    def test_upsert_new(self):
        iid = db.upsert_ioc("185.1.2.3", "ip", "test")
        assert iid > 0

    def test_upsert_deduplicates(self):
        db.upsert_ioc("185.1.2.3", "ip")
        db.upsert_ioc("185.1.2.3", "ip")
        count = db.get_conn().execute(
            "SELECT COUNT(*) FROM ioc_indicators WHERE value='185.1.2.3'"
        ).fetchone()[0]
        assert count == 1

    def test_get_existing(self):
        db.upsert_ioc("evil.com", "domain")
        row = db.get_ioc("evil.com")
        assert row is not None
        assert row["type"] == "domain"
        assert row["threat_level"] == "UNKNOWN"

    def test_get_nonexistent(self):
        assert db.get_ioc("nothere.xyz") is None

    def test_update_vt(self):
        db.upsert_ioc("bad.ru", "domain")
        Config.VT_MALICIOUS_THRESHOLD = 0.15
        threat = db.update_ioc_vt("bad.ru", 35, 70, 0.50, {"malicious": 35})
        assert threat == "MALICIOUS"
        row = db.get_ioc("bad.ru")
        assert row["vt_detections"] == 35
        assert row["threat_level"] == "MALICIOUS"

    def test_update_vt_clean(self):
        db.upsert_ioc("google.com", "domain")
        Config.VT_MALICIOUS_THRESHOLD = 0.15
        threat = db.update_ioc_vt("google.com", 0, 70, 0.0, {})
        assert threat == "CLEAN"

    def test_list_paged(self):
        for i in range(60):
            db.upsert_ioc(f"192.0.2.{i}", "ip")
        rows, total = db.list_iocs(page=1, per_page=50)
        assert total == 60
        assert len(rows) == 50

    def test_list_filtered_by_type(self):
        db.upsert_ioc("1.2.3.4", "ip")
        db.upsert_ioc("evil.com", "domain")
        rows, total = db.list_iocs(ioc_type="ip")
        assert total == 1
        assert rows[0]["type"] == "ip"

    def test_list_filtered_by_search(self):
        db.upsert_ioc("ransomware.xyz", "domain")
        db.upsert_ioc("clean-site.com", "domain")
        rows, total = db.list_iocs(search="ransomware")
        assert total == 1
        assert "ransomware" in rows[0]["value"]


class TestAlertCRUD:
    def test_create_alert(self):
        aid = db.create_alert("1.2.3.4", "ip", "HIGH", "log line", {"score": 0.8})
        assert aid > 0

    def test_list_alerts(self):
        db.create_alert("evil.com", "domain", "CRITICAL")
        rows, total = db.list_alerts()
        assert total >= 1

    def test_acknowledge(self):
        aid = db.create_alert("1.2.3.4", "ip", "HIGH")
        db.acknowledge_alert(aid, "analyst1", "verified")
        rows, _ = db.list_alerts()
        row = next(r for r in rows if r["id"] == aid)
        assert row["status"] == "ACKNOWLEDGED"
        assert row["acknowledged_by"] == "analyst1"

    def test_false_positive(self):
        aid = db.create_alert("1.2.3.4", "ip", "MEDIUM")
        db.false_positive_alert(aid)
        rows, _ = db.list_alerts()
        row = next(r for r in rows if r["id"] == aid)
        assert row["status"] == "FALSE_POSITIVE"

    def test_count_today(self):
        db.create_alert("a.com", "domain", "HIGH")
        db.create_alert("b.com", "domain", "MEDIUM")
        assert db.count_alerts_today() >= 2


class TestFeedSync:
    def test_log_feed_sync(self):
        db.log_feed_sync("TestFeed", 1500, 2.3, "SUCCESS")
        history = db.get_feed_sync_history()
        assert any(h["feed_name"] == "TestFeed" for h in history)

    def test_log_feed_sync_error(self):
        db.log_feed_sync("TestFeed", 0, 0.5, "ERROR", "Connection refused")
        history = db.get_feed_sync_history()
        assert any(h["status"] == "ERROR" for h in history)
