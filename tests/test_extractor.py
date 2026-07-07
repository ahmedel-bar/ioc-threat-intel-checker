import pytest
from app.parsing.extractor import extract, IOC


def types(iocs: list[IOC]) -> set[str]:
    return {i.type for i in iocs}


def values(iocs: list[IOC]) -> set[str]:
    return {i.value for i in iocs}


class TestIPExtraction:
    def test_public_ip(self):
        iocs = extract("Connection from 185.220.101.47 detected")
        assert any(i.value == "185.220.101.47" and i.type == "ip" for i in iocs)

    def test_rfc1918_filtered(self):
        iocs = extract("src=10.0.1.5 dst=192.168.1.1", filter_rfc1918=True)
        assert not any(i.type == "ip" for i in iocs)

    def test_rfc1918_allowed(self):
        iocs = extract("src=10.0.1.5", filter_rfc1918=False)
        assert any(i.value == "10.0.1.5" for i in iocs)

    def test_loopback_filtered(self):
        iocs = extract("127.0.0.1 localhost connection", filter_rfc1918=True)
        assert not any(i.value == "127.0.0.1" for i in iocs)

    def test_multiple_ips(self):
        iocs = extract("hosts 1.2.3.4 and 5.6.7.8 flagged")
        ip_values = {i.value for i in iocs if i.type == "ip"}
        assert ip_values == {"1.2.3.4", "5.6.7.8"}

    def test_ip_deduplication(self):
        iocs = extract("1.2.3.4 1.2.3.4 1.2.3.4")
        assert sum(1 for i in iocs if i.value == "1.2.3.4") == 1


class TestHashExtraction:
    def test_md5(self):
        iocs = extract("file hash: d41d8cd98f00b204e9800998ecf8427e")
        assert any(i.type == "md5" for i in iocs)

    def test_sha1(self):
        iocs = extract("sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert any(i.type == "sha1" for i in iocs)

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract(f"hash={h}")
        assert any(i.value == h and i.type == "sha256" for i in iocs)

    def test_sha256_not_also_matched_as_sha1_or_md5(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract(h)
        hash_iocs = [i for i in iocs if i.type in ("md5", "sha1", "sha256")]
        assert len(hash_iocs) == 1
        assert hash_iocs[0].type == "sha256"

    def test_hashes_lowercase(self):
        iocs = extract("ABCDEF1234567890ABCDEF1234567890")
        assert any(i.value == "abcdef1234567890abcdef1234567890" for i in iocs)


class TestURLExtraction:
    def test_http_url(self):
        iocs = extract("request to http://evil.ru/malware.exe blocked")
        assert any(i.type == "url" for i in iocs)

    def test_https_url(self):
        iocs = extract("beacon: https://c2.badguy.xyz/check")
        urls = [i for i in iocs if i.type == "url"]
        assert len(urls) >= 1
        assert any("c2.badguy.xyz" in i.value for i in urls)

    def test_url_lowercase(self):
        iocs = extract("GET HTTP://EVIL.COM/path")
        assert any(i.type == "url" and "evil.com" in i.value for i in iocs)


class TestDomainExtraction:
    def test_known_domain(self):
        iocs = extract("query: malware-c2.xyz IN A")
        assert any(i.type == "domain" and "malware-c2.xyz" in i.value for i in iocs)

    def test_url_domain_not_double_counted(self):
        iocs = extract("https://evil.com/path")
        domains = [i for i in iocs if i.type == "domain" and "evil.com" in i.value]
        urls = [i for i in iocs if i.type == "url" and "evil.com" in i.value]
        # Should not have both a domain and URL pointing to same host
        assert not (domains and urls)


class TestMixedLog:
    def test_firewall_log(self):
        log = (
            "2026-06-10T12:00:01Z TRAFFIC ALLOW 185.220.101.47:45123 "
            "-> 10.0.0.5:443 rule=block-c2"
        )
        iocs = extract(log, filter_rfc1918=True)
        assert any(i.value == "185.220.101.47" for i in iocs)
        assert not any(i.value == "10.0.0.5" for i in iocs)

    def test_web_log_with_url(self):
        log = '203.1.2.3 - - [10/Jun/2026] "GET https://phish.xyz/login HTTP/1.1" 200'
        iocs = extract(log)
        assert "ip" in types(iocs)

    def test_endpoint_log_with_hash(self):
        log = "Process hash=d41d8cd98f00b204e9800998ecf8427e User=CORP\\admin"
        iocs = extract(log)
        assert "md5" in types(iocs)

    def test_empty_string(self):
        assert extract("") == []

    def test_no_iocs(self):
        assert extract("no indicators of compromise here just normal text") == []
