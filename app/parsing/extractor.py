import re
from dataclasses import dataclass

# Pre-compiled patterns — order matters: sha256 before sha1 before md5 to avoid prefix collisions
_PAT_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_PAT_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_PAT_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_PAT_URL    = re.compile(r'https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?', re.IGNORECASE)
_PAT_IP     = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_PAT_DOMAIN = re.compile(
    r'\b(?!(?:\d+\.)+\d+\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|info|biz|co|gov|edu|xyz|ru|cn|de|uk|fr|nl|br|au|jp|in'
    r'|cc|tk|top|pw|site|online|club|tech|live|cf|ga|gq|ml|monster|cyou)\b',
    re.IGNORECASE
)

# RFC 1918 + loopback + APIPA ranges to filter
_RFC1918 = re.compile(
    r'^(10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.)'
)


@dataclass(slots=True)
class IOC:
    value: str
    type: str   # ip | md5 | sha1 | sha256 | domain | url


def extract(text: str, filter_rfc1918: bool = True) -> list[IOC]:
    iocs: list[IOC] = []
    seen: set[str] = set()

    def _add(value: str, kind: str):
        v = value.lower() if kind in ("domain", "url") else value
        if v not in seen:
            seen.add(v)
            iocs.append(IOC(value=v, type=kind))

    # Strip URLs before domain extraction to avoid double-counting
    url_spans: set[tuple[int, int]] = set()
    for m in _PAT_URL.finditer(text):
        _add(m.group(), "url")
        url_spans.add((m.start(), m.end()))

    # Remove URL spans from text before domain/hash extraction
    clean = text
    for start, end in sorted(url_spans, reverse=True):
        clean = clean[:start] + " " * (end - start) + clean[end:]

    # Hashes — sha256 first to prevent shorter hash regexes matching a prefix
    sha256_spans: set[tuple[int, int]] = set()
    for m in _PAT_SHA256.finditer(clean):
        _add(m.group().lower(), "sha256")
        sha256_spans.add((m.start(), m.end()))
    for start, end in sorted(sha256_spans, reverse=True):
        clean = clean[:start] + " " * (end - start) + clean[end:]

    sha1_spans: set[tuple[int, int]] = set()
    for m in _PAT_SHA1.finditer(clean):
        _add(m.group().lower(), "sha1")
        sha1_spans.add((m.start(), m.end()))
    for start, end in sorted(sha1_spans, reverse=True):
        clean = clean[:start] + " " * (end - start) + clean[end:]

    for m in _PAT_MD5.finditer(clean):
        _add(m.group().lower(), "md5")

    # IPs
    for m in _PAT_IP.finditer(clean):
        ip = m.group()
        if filter_rfc1918 and _RFC1918.match(ip):
            continue
        _add(ip, "ip")

    # Domains (from clean text, after URL removal)
    for m in _PAT_DOMAIN.finditer(clean):
        dom = m.group().lower()
        # Skip if it's just part of an already-seen hash or number
        if re.match(r'^[0-9a-f.]+$', dom):
            continue
        _add(dom, "domain")

    return iocs
