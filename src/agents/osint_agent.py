from __future__ import annotations
from typing import List, Set


from models import OSINTResult, ShodanHost
from agents.base import BaseAgent
from src.util import fetch_json
from src.settings import SHODAN_API_KEY

class OSINTAgent(BaseAgent):
    name = "osint"


    def _crtsh(self, domain: str) -> List[str]:
        # Використовуємо публічний інтерфейс crt.sh (без ключа)
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            data = fetch_json(url)
        except Exception:
            return []
        names: Set[str] = set()
        if isinstance(data, list):
            for row in data:
                nv = row.get("name_value")
                if not nv:
                    continue
                # name_value може містити кілька CN через \n
                for n in str(nv).split("\n"):
                    n = n.strip().lower().strip('.')
                    if n.endswith('.' + domain) or n == domain:
                        names.add(n)
        return sorted(names)


    def _shodan(self, ips: List[str]) -> List[ShodanHost]:
        if not SHODAN_API_KEY:
         return []
        try:
            import shodan
        except Exception:
            return []
        api = shodan.Shodan(SHODAN_API_KEY)
        out: List[ShodanHost] = []
        for ip in ips:
            try:
                info = api.host(ip)
                out.append(
                    ShodanHost(
                        ip=ip,
                        ports=sorted(info.get("ports", [])),
                        org=info.get("org"),
                        hostnames=info.get("hostnames", []) or [],
                    )
                )
            except Exception:
                # пропускаємо помилки/ліміти
                continue
        return out


    def run(self, domain: str) -> OSINTResult:
        crt = self._crtsh(domain)
        # якщо DNS-агент передав A‑записи у спільному контексті — використаємо їх для Shodan
        a_records = self.get_shared("a_records", []) or []
        shodan_hosts = self._shodan(a_records)
        return OSINTResult(crtsh_names=crt, shodan_hosts=shodan_hosts)