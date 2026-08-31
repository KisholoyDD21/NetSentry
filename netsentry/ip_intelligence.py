"""
IP intelligence: WHOIS, ASN, geolocation/country, and a lightweight
reputation score.

- Geolocation / ISP / ASN come from ip-api.com (free, no key required).
- WHOIS/RDAP comes from ipwhois (queries regional internet registries
  directly -- no external API key needed).
- Reputation uses AbuseIPDB when the user supplies an API key in
  config.json; otherwise it falls back to a transparent local heuristic
  (private-range check + ASN/org text matching against known hosting/VPN
  keywords) and is labeled accordingly so results are never presented as
  more authoritative than they are.

Lookups are cached in SQLite (ip_intel_cache) with a configurable TTL, and
batches run concurrently via asyncio + a thread executor since `requests`
and `ipwhois` are both synchronous/blocking.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta
from typing import Optional

import requests

from netsentry.database import Database
from netsentry.utils import load_config, is_private_ip, setup_logger

logger = setup_logger(__name__)

_HOSTING_KEYWORDS = (
    "amazon", "aws", "google cloud", "digitalocean", "ovh", "hetzner",
    "azure", "microsoft corporation", "linode", "vultr", "alibaba",
    "hostinger", "cloudflare",
)


class IPIntelligence:
    def __init__(self, db: Database):
        self.db = db
        cfg = load_config()["ip_intelligence"]
        self.cfg = cfg
        self.geo_api_template = cfg["geo_api"]
        self.abuseipdb_key = cfg.get("abuseipdb_api_key", "").strip()
        self.timeout = cfg.get("request_timeout_seconds", 5)
        self.cache_ttl = cfg.get("cache_ttl_seconds", 3600)

    # -- cache -------------------------------------------------------------

    def _cache_fresh(self, row) -> bool:
        if row is None:
            return False
        try:
            cached_at = datetime.fromisoformat(row["cached_at"])
        except Exception:
            return False
        return datetime.now() - cached_at < timedelta(seconds=self.cache_ttl)

    # -- geolocation / ASN / ISP -----------------------------------------

    def _fetch_geo(self, ip: str) -> dict:
        url = self.geo_api_template.format(ip=ip)
        try:
            resp = requests.get(url, timeout=self.timeout)
            data = resp.json()
        except Exception as exc:
            logger.warning("Geo lookup failed for %s: %s", ip, exc)
            return {}
        if data.get("status") != "success":
            return {}
        return {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
        }

    # -- WHOIS / RDAP --------------------------------------------------

    def _fetch_whois(self, ip: str) -> dict:
        try:
            from ipwhois import IPWhois
        except ImportError:
            return {"error": "ipwhois not installed"}
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)
            return {
                "asn": result.get("asn"),
                "asn_description": result.get("asn_description"),
                "asn_country_code": result.get("asn_country_code"),
                "network_name": (result.get("network") or {}).get("name"),
                "network_cidr": (result.get("network") or {}).get("cidr"),
                "entities": result.get("entities", []),
            }
        except Exception as exc:
            logger.warning("WHOIS lookup failed for %s: %s", ip, exc)
            return {"error": str(exc)}

    # -- reputation ------------------------------------------------------

    def _fetch_abuseipdb(self, ip: str) -> Optional[dict]:
        if not self.abuseipdb_key:
            return None
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                timeout=self.timeout,
            )
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            label = "malicious" if score >= 50 else ("suspicious" if score >= 10 else "clean")
            return {"reputation_score": score, "reputation_label": f"{label} (AbuseIPDB)"}
        except Exception as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None

    def _heuristic_reputation(self, ip: str, geo: dict, whois: dict) -> dict:
        if is_private_ip(ip):
            return {"reputation_score": 0, "reputation_label": "private/reserved range"}

        org_text = " ".join(
            str(x) for x in (geo.get("org"), geo.get("isp"), whois.get("asn_description"))
            if x
        ).lower()

        score = 15  # baseline "unknown, no evidence either way"
        notes = []
        if any(kw in org_text for kw in _HOSTING_KEYWORDS):
            score += 20
            notes.append("hosted on cloud/VPS infrastructure")

        if score >= 30:
            label = f"heuristic-suspicious ({', '.join(notes)})"
        else:
            label = "heuristic-neutral (configure AbuseIPDB key for real scoring)"
        return {"reputation_score": score, "reputation_label": label}

    # -- public API --------------------------------------------------------

    def lookup(self, ip: str, force_refresh: bool = False) -> dict:
        if not force_refresh:
            cached = self.db.get_ip_cache(ip)
            if cached and self._cache_fresh(cached):
                return dict(cached)

        geo = self._fetch_geo(ip) if not is_private_ip(ip) else {}
        whois = self._fetch_whois(ip) if not is_private_ip(ip) else {}

        reputation = self._fetch_abuseipdb(ip) or self._heuristic_reputation(ip, geo, whois)

        result = {**geo, "whois": whois, **reputation}
        try:
            self.db.upsert_ip_cache(ip, result)
        except Exception:
            logger.exception("Failed to cache IP intel for %s", ip)
        result["ip"] = ip
        return result

    async def _lookup_async(self, ip: str, loop: asyncio.AbstractEventLoop) -> dict:
        return await loop.run_in_executor(None, self.lookup, ip)

    async def batch_lookup_async(self, ips: list[str]) -> dict[str, dict]:
        loop = asyncio.get_running_loop()
        tasks = [self._lookup_async(ip, loop) for ip in dict.fromkeys(ips)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = {}
        for ip, res in zip(dict.fromkeys(ips), results):
            if isinstance(res, Exception):
                logger.warning("Batch lookup failed for %s: %s", ip, res)
                continue
            out[ip] = res
        return out

    def batch_lookup(self, ips: list[str]) -> dict[str, dict]:
        """Synchronous entry point -- call from a worker thread, not the GUI thread."""
        return asyncio.run(self.batch_lookup_async(ips))
