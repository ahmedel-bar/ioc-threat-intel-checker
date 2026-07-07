"""
Geo-IP enrichment via ip-api.com (free, no key required).
Results are cached in-process; falls back to empty dict on any failure.
"""
import logging
import requests

logger = logging.getLogger(__name__)

_CACHE: dict[str, dict] = {}
_ENABLED = True   # set to False to disable without changing config


def lookup(ip: str) -> dict:
    """Return {country_code, country_name, city, org, asn} or {} on failure."""
    if not _ENABLED or not ip:
        return {}
    if ip in _CACHE:
        return _CACHE[ip]
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,org,as"},
            timeout=5,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                geo = {
                    "country_code": d.get("countryCode", ""),
                    "country_name": d.get("country", ""),
                    "city": d.get("city", ""),
                    "org": d.get("org", ""),
                    "asn": d.get("as", ""),
                }
                _CACHE[ip] = geo
                return geo
    except Exception as exc:
        logger.debug("[GeoIP] lookup failed for %s: %s", ip, exc)
    return {}
