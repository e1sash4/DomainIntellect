from __future__ import annotations
import os
import time
import requests
from typing import List, Dict, Any, Optional

from models import VirusTotalResult, VTStats

from settings import VIRUSTOTAL_API_KEY

VT_API = "https://www.virustotal.com/api/v3"

def _hdr() -> Dict[str, str]:
    key = VIRUSTOTAL_API_KEY
    if not key:
        raise RuntimeError("VirusTotal API key is not set (env VIRUSTOTAL_API_KEY or VT_API_KEY).")
    return {"x-apikey": key}

def _safe_get(url: str, params: Dict[str, Any] | None = None) -> Optional[Dict[str, Any]]:
    resp = requests.get(url, headers=_hdr(), params=params or {}, timeout=30)
    if resp.status_code == 429:
        # простий фолбек на ліміт: трохи зачекати і спробувати ще раз один раз
        time.sleep(2.0)
        resp = requests.get(url, headers=_hdr(), params=params or {}, timeout=30)
    if resp.status_code == 200:
        try:
            return resp.json()
        except Exception:
            return None
    return None

class VirusTotalAgent:
    """Отримує репутацію домену, статути аналізу, пов’язані IP/субдомени."""

    def _domain_overview(self, domain: str) -> Optional[Dict[str, Any]]:
        return _safe_get(f"{VT_API}/domains/{domain}")

    def _domain_subdomains(self, domain: str, limit: int = 75) -> List[str]:
        # relationships: subdomains
        names: List[str] = []
        url = f"{VT_API}/domains/{domain}/relationships/subdomains"
        params = {"limit": min(limit, 75)}
        data = _safe_get(url, params)
        if not data:
            return names
        for item in data.get("data", []):
            attr = item.get("id")
            if attr:
                names.append(attr)
        return names

    def _domain_resolutions(self, domain: str, limit: int = 75) -> List[str]:
        # relationships: resolutions -> IPs
        ips: set[str] = set()
        url = f"{VT_API}/domains/{domain}/relationships/resolutions"
        params = {"limit": min(limit, 75)}
        data = _safe_get(url, params)
        if not data:
            return []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            ip = attrs.get("ip_address")
            if ip:
                ips.add(ip)
        return list(ips)

    def _domain_subdomains_full(self, domain: str, limit: int = 75) -> Optional[Dict[str, Any]]:
        url = f"{VT_API}/domains/{domain}/relationships/subdomains"
        params = {"limit": min(limit, 75)}
        return _safe_get(url, params)

    def _domain_resolutions_full(self, domain: str, limit: int = 75) -> Optional[Dict[str, Any]]:
        url = f"{VT_API}/domains/{domain}/relationships/resolutions"
        params = {"limit": min(limit, 75)}
        return _safe_get(url, params)

    def run(self, domain: str) -> VirusTotalResult:
        ov = self._domain_overview(domain)
        vt = VirusTotalResult(domain=domain)

        # 1) збережемо повністю, щоб ти міг виводити "усю інформацію"
        vt.raw = ov

        # 2) вибірково витягнемо корисні поля для швидкого огляду (як і було)
        if ov and "data" in ov and "attributes" in ov["data"]:
            at = ov["data"]["attributes"]
            stats = at.get("last_analysis_stats") or {}
            vt.last_analysis_stats = VTStats(
                harmless=stats.get("harmless", 0),
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                undetected=stats.get("undetected", 0),
                timeout=stats.get("timeout", 0),
            )
            vt.reputation = at.get("reputation")
            vt.categories = at.get("categories") or {}
            vt.last_analysis_date = at.get("last_analysis_date")
            vt.total_votes = at.get("total_votes") or {}
            vt.whois = at.get("whois")
            vt.registrar = at.get("registrar")
            vt.tags = at.get("tags") or []

        # 3) (як і було) короткі списки + (нове) повні сирі відповіді
        try:
            raw_subs = self._domain_subdomains_full(domain)
            vt.raw_subdomains = raw_subs
            vt.related_subdomains = [
                item.get("id") for item in (raw_subs or {}).get("data", []) if item.get("id")
            ]
        except Exception:
            pass

        try:
            raw_res = self._domain_resolutions_full(domain)
            vt.raw_resolutions = raw_res
            ips = set()
            for item in (raw_res or {}).get("data", []):
                attrs = item.get("attributes", {})
                ip = attrs.get("ip_address")
                if ip:
                    ips.add(ip)
            vt.related_ips = list(ips)
        except Exception:
            pass

        return vt
