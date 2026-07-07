import time
import pytest
from unittest.mock import patch, MagicMock
from app.enrichment.virustotal import VTBroker, TokenBucket


class TestTokenBucket:
    def test_initial_tokens(self):
        bucket = TokenBucket(rate_per_minute=4)
        # Should have 4 tokens and acquire immediately
        t0 = time.monotonic()
        bucket.acquire()
        assert time.monotonic() - t0 < 0.5

    def test_consumes_token(self):
        bucket = TokenBucket(rate_per_minute=60)  # 1/sec
        for _ in range(5):
            bucket.acquire()


class TestVTBroker:
    def test_no_key_returns_none(self):
        broker = VTBroker("")
        result = broker.query("1.2.3.4", "ip")
        assert result is None

    def test_endpoint_ip(self):
        broker = VTBroker("fake-key")
        ep = broker._endpoint("1.2.3.4", "ip")
        assert "ip_addresses/1.2.3.4" in ep

    def test_endpoint_hash(self):
        broker = VTBroker("fake-key")
        for htype in ("md5", "sha1", "sha256"):
            ep = broker._endpoint("abc123" + "0" * 26, htype)
            assert "/files/" in ep

    def test_endpoint_domain(self):
        broker = VTBroker("fake-key")
        ep = broker._endpoint("evil.com", "domain")
        assert "/domains/evil.com" in ep

    def test_endpoint_url(self):
        broker = VTBroker("fake-key")
        ep = broker._endpoint("https://evil.com/path", "url")
        assert "/urls/" in ep

    def test_parse_response(self):
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 35, "suspicious": 5,
                        "undetected": 20, "harmless": 10,
                    }
                }
            }
        }
        result = VTBroker._parse(data)
        assert result["detections"] == 40
        assert result["total"] == 70
        assert result["score"] == pytest.approx(40 / 70, abs=0.001)

    def test_parse_404_response(self):
        result = VTBroker._parse({})
        assert result["detections"] == 0
        assert result["score"] == 0.0

    @patch("app.enrichment.virustotal.requests.get")
    def test_query_malicious(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 40, "suspicious": 0,
                        "undetected": 10, "harmless": 20,
                    }
                }
            }
        }
        mock_get.return_value = mock_resp

        broker = VTBroker("test-api-key", rate_per_minute=60)
        result = broker.query("185.220.101.47", "ip")
        assert result is not None
        assert result["detections"] == 40
        assert result["score"] > 0.5

    @patch("app.enrichment.virustotal.requests.get")
    def test_query_clean(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0,
                        "undetected": 5, "harmless": 65,
                    }
                }
            }
        }
        mock_get.return_value = mock_resp

        broker = VTBroker("test-api-key", rate_per_minute=60)
        result = broker.query("8.8.8.8", "ip")
        assert result["score"] == 0.0

    @patch("app.enrichment.virustotal.requests.get")
    def test_daily_quota_exhaustion(self, mock_get):
        broker = VTBroker("test-key", rate_per_minute=60)
        broker._queries_today = 500  # Exhaust quota
        result = broker.query("1.2.3.4", "ip")
        assert result is None
        mock_get.assert_not_called()
